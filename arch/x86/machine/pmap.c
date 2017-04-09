/*
 * Copyright (c) 2010-2017 Richard Braun.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * TODO Review locking.
 */

#include <stddef.h>
#include <string.h>

#include <kern/assert.h>
#include <kern/cpumap.h>
#include <kern/error.h>
#include <kern/init.h>
#include <kern/kmem.h>
#include <kern/list.h>
#include <kern/macros.h>
#include <kern/mutex.h>
#include <kern/panic.h>
#include <kern/param.h>
#include <kern/percpu.h>
#include <kern/spinlock.h>
#include <kern/sprintf.h>
#include <kern/syscnt.h>
#include <kern/thread.h>
#include <machine/biosmem.h>
#include <machine/boot.h>
#include <machine/cpu.h>
#include <machine/lapic.h>
#include <machine/pmap.h>
#include <machine/trap.h>
#include <machine/types.h>
#include <vm/vm_kmem.h>
#include <vm/vm_page.h>
#include <vm/vm_prot.h>

/*
 * Properties of a page translation level.
 */
struct pmap_pt_level {
    unsigned int skip;
    unsigned int bits;
    unsigned int ptes_per_pt;
    pmap_pte_t mask;
};

/*
 * Table of page translation properties.
 */
static struct pmap_pt_level pmap_pt_levels[] __read_mostly = {
    { PMAP_L0_SKIP, PMAP_L0_BITS, PMAP_L0_PTES_PER_PT, PMAP_L0_MASK },
    { PMAP_L1_SKIP, PMAP_L1_BITS, PMAP_L1_PTES_PER_PT, PMAP_L1_MASK },
#if PMAP_NR_LEVELS > 2
    { PMAP_L2_SKIP, PMAP_L2_BITS, PMAP_L2_PTES_PER_PT, PMAP_L2_MASK },
#if PMAP_NR_LEVELS > 3
    { PMAP_L3_SKIP, PMAP_L3_BITS, PMAP_L3_PTES_PER_PT, PMAP_L3_MASK },
#endif /* PMAP_NR_LEVELS > 3 */
#endif /* PMAP_NR_LEVELS > 2 */
};

/*
 * Per-CPU page tables.
 */
struct pmap_cpu_table {
    struct list node;
    phys_addr_t root_ptp_pa;
};

struct pmap {
    struct pmap_cpu_table *cpu_tables[X15_MAX_CPUS];
};

/*
 * Type for page table walking functions.
 *
 * See pmap_walk_vas().
 */
typedef void (*pmap_walk_fn_t)(phys_addr_t pa, unsigned int index,
                               unsigned int level);

static struct pmap kernel_pmap_store __read_mostly;
struct pmap *kernel_pmap __read_mostly = &kernel_pmap_store;

/*
 * The kernel per-CPU page tables are used early enough during bootstrap
 * that using a percpu variable would actually become ugly. This array
 * is rather small anyway.
 */
static struct pmap_cpu_table kernel_pmap_cpu_tables[X15_MAX_CPUS] __read_mostly;

struct pmap *pmap_current_ptr __percpu;

#ifdef X15_X86_PAE

/*
 * Alignment required on page directory pointer tables.
 */
#define PMAP_PDPT_ALIGN 32

/*
 * "Hidden" kernel root page tables for PAE mode.
 */
static pmap_pte_t pmap_cpu_kpdpts[X15_MAX_CPUS][PMAP_L2_PTES_PER_PT]
    __read_mostly __aligned(PMAP_PDPT_ALIGN);

#endif /* X15_X86_PAE */

/*
 * Flags related to page protection.
 */
#define PMAP_PTE_PROT_MASK PMAP_PTE_RW

/*
 * Table used to convert machine independent protection flags to architecture
 * specific PTE bits.
 */
static pmap_pte_t pmap_prot_table[VM_PROT_ALL + 1] __read_mostly;

/*
 * Structures related to inter-processor page table updates.
 */

#define PMAP_UPDATE_OP_ENTER    1
#define PMAP_UPDATE_OP_REMOVE   2
#define PMAP_UPDATE_OP_PROTECT  3

struct pmap_update_enter_args {
    uintptr_t va;
    phys_addr_t pa;
    int prot;
    int flags;
};

struct pmap_update_remove_args {
    uintptr_t start;
    uintptr_t end;
};

struct pmap_update_protect_args {
    uintptr_t start;
    uintptr_t end;
    int prot;
};

struct pmap_update_op {
    struct cpumap cpumap;
    unsigned int operation;

    union {
        struct pmap_update_enter_args enter_args;
        struct pmap_update_remove_args remove_args;
        struct pmap_update_protect_args protect_args;
    };
};

/*
 * Maximum number of operations that can be batched before an implicit
 * update.
 */
#define PMAP_UPDATE_MAX_OPS 32

/*
 * List of update operations.
 *
 * A list of update operations is a container of operations that are pending
 * for a pmap. Updating can be implicit, e.g. when a list has reached its
 * maximum size, or explicit, when pmap_update() is called. Operation lists
 * are thread-local objects.
 *
 * The cpumap is the union of all processors affected by at least one
 * operation.
 */
struct pmap_update_oplist {
    struct cpumap cpumap;
    struct pmap *pmap;
    unsigned int nr_ops;
    struct pmap_update_op ops[PMAP_UPDATE_MAX_OPS];
} __aligned(CPU_L1_SIZE);

static unsigned int pmap_oplist_tsd_key __read_mostly;

/*
 * Statically allocated data for the main booter thread.
 */
static struct cpumap pmap_booter_cpumap __initdata;
static struct pmap_update_oplist pmap_booter_oplist __initdata;

/*
 * Each regular thread gets an operation list from this cache.
 */
static struct kmem_cache pmap_update_oplist_cache;

/*
 * Queue holding update requests from remote processors.
 */
struct pmap_update_queue {
    struct spinlock lock;
    struct list requests;
};

/*
 * Syncer thread.
 *
 * There is one such thread per processor. They are the recipients of
 * update requests, providing thread context for the mapping operations
 * they perform.
 */
struct pmap_syncer {
    struct thread *thread;
    struct pmap_update_queue queue;
    struct syscnt sc_updates;
    struct syscnt sc_update_enters;
    struct syscnt sc_update_removes;
    struct syscnt sc_update_protects;
} __aligned(CPU_L1_SIZE);

static void pmap_sync(void *arg);

static struct pmap_syncer pmap_syncer __percpu;

/*
 * Maximum number of mappings for which individual TLB invalidations can be
 * performed. Global TLB flushes are done beyond this value.
 */
#define PMAP_UPDATE_MAX_MAPPINGS 64

/*
 * Per processor request, queued on a remote processor.
 *
 * The number of mappings is used to determine whether it's best to flush
 * individual TLB entries or globally flush the TLB.
 */
struct pmap_update_request {
    struct list node;
    struct spinlock lock;
    struct thread *sender;
    const struct pmap_update_oplist *oplist;
    unsigned int nr_mappings;
    int done;
    int error;
} __aligned(CPU_L1_SIZE);

/*
 * Per processor array of requests.
 *
 * When an operation list is to be applied, the thread triggering the update
 * acquires the processor-local array of requests and uses it to queue requests
 * on remote processors.
 */
struct pmap_update_request_array {
    struct pmap_update_request requests[X15_MAX_CPUS];
    struct mutex lock;
};

static struct pmap_update_request_array pmap_update_request_array __percpu;

static int pmap_do_remote_updates __read_mostly;

static struct kmem_cache pmap_cache;

#ifdef X15_X86_PAE
static char pmap_panic_no_pae[] __bootdata
    = "pmap: PAE not supported";
#endif /* X15_X86_PAE */
static char pmap_panic_inval_msg[] __bootdata
    = "pmap: invalid physical address";
static char pmap_panic_directmap_msg[] __bootdata
    = "pmap: invalid direct physical mapping";

static __always_inline unsigned long
pmap_pte_index(uintptr_t va, const struct pmap_pt_level *pt_level)
{
    return ((va >> pt_level->skip) & ((1UL << pt_level->bits) - 1));
}

static void __boot
pmap_boot_enter(pmap_pte_t *root_ptp, uintptr_t va, phys_addr_t pa,
                unsigned long pgsize)
{
    const struct pmap_pt_level *pt_level, *pt_levels;
    pmap_pte_t *pt, *ptp, *pte, bits;
    unsigned int level, last_level;

    if (pa != (pa & PMAP_PA_MASK)) {
        boot_panic(pmap_panic_inval_msg);
    }

    switch (pgsize) {
#ifdef __LP64__
    case (1 << PMAP_L2_SKIP):
        bits = PMAP_PTE_PS;
        last_level = 2;
        break;
#endif /* __LP64__ */
    case (1 << PMAP_L1_SKIP):
        bits = PMAP_PTE_PS;
        last_level = 1;
        break;
    default:
        bits = 0;
        last_level = 0;
    }

    pt_levels = (void *)BOOT_VTOP((uintptr_t)pmap_pt_levels);
    pt = root_ptp;

    for (level = PMAP_NR_LEVELS - 1; level != last_level; level--) {
        pt_level = &pt_levels[level];
        pte = &pt[pmap_pte_index(va, pt_level)];

        if (*pte != 0) {
            ptp = (void *)(uintptr_t)(*pte & PMAP_PA_MASK);
        } else {
            ptp = biosmem_bootalloc(1);
            *pte = ((uintptr_t)ptp | PMAP_PTE_RW | PMAP_PTE_P)
                   & pt_level->mask;
        }

        pt = ptp;
    }

    pt_level = &pt_levels[last_level];
    pte = &pt[pmap_pte_index(va, pt_level)];
    *pte = (pa & PMAP_PA_MASK) | PMAP_PTE_RW | PMAP_PTE_P | bits;
}

static unsigned long __boot
pmap_boot_get_pgsize(void)
{
    unsigned int eax, ebx, ecx, edx;

#ifdef __LP64__
    eax = 0x80000000;
    cpu_cpuid(&eax, &ebx, &ecx, &edx);

    if (eax <= 0x80000000) {
        goto out;
    }

    eax = 0x80000001;
    cpu_cpuid(&eax, &ebx, &ecx, &edx);

    if (edx & CPU_FEATURE4_1GP) {
        return (1 << PMAP_L2_SKIP);
    }

out:
    return (1 << PMAP_L1_SKIP);
#else /* __LP64__ */
    eax = 0;
    cpu_cpuid(&eax, &ebx, &ecx, &edx);

    if (eax == 0) {
        goto out;
    }

    eax = 1;
    cpu_cpuid(&eax, &ebx, &ecx, &edx);

#ifdef X15_X86_PAE
    if (!(edx & CPU_FEATURE2_PAE)) {
        boot_panic(pmap_panic_no_pae);
    }

    return (1 << PMAP_L1_SKIP);
#else /* X15_X86_PAE */
    if (edx & CPU_FEATURE2_PSE) {
        return (1 << PMAP_L1_SKIP);
    }
#endif /* X15_X86_PAE */

out:
    return PAGE_SIZE;
#endif /* __LP64__ */
}

#ifdef __LP64__
#define pmap_boot_enable_pgext(pgsize) ((void)(pgsize))
#else /* __LP64__ */
static void __boot
pmap_boot_enable_pgext(unsigned long pgsize)
{
    if (pgsize == PAGE_SIZE) {
        return;
    }

    /*
     * On 64-bits systems, PAE is already enabled.
     *
     * See the boot module.
     */
#ifdef X15_X86_PAE
    cpu_enable_pae();
#else /* X15_X86_PAE */
    cpu_enable_pse();
#endif /* X15_X86_PAE */
}
#endif /* __LP64__ */

pmap_pte_t * __boot
pmap_setup_paging(void)
{
    struct pmap_cpu_table *cpu_table;
    phys_addr_t pa, directmap_end;
    unsigned long i, size, pgsize;
    pmap_pte_t *root_ptp;
    uintptr_t va;

    /* Use large pages for the direct physical mapping when possible */
    pgsize = pmap_boot_get_pgsize();
    pmap_boot_enable_pgext(pgsize);

    /*
     * Create the initial mappings. The first is for the .boot section
     * and acts as the mandatory identity mapping. The second is the
     * direct physical mapping of physical memory.
     */

#ifdef X15_X86_PAE
    root_ptp = (void *)BOOT_VTOP((uintptr_t)pmap_cpu_kpdpts[0]);
#else /* X15_X86_PAE */
    root_ptp = biosmem_bootalloc(1);
#endif /* X15_X86_PAE */

    va = vm_page_trunc((uintptr_t)&_boot);
    pa = va;
    size = vm_page_round((uintptr_t)&_boot_end) - va;

    for (i = 0; i < size; i += PAGE_SIZE) {
        pmap_boot_enter(root_ptp, va, pa, PAGE_SIZE);
        va += PAGE_SIZE;
        pa += PAGE_SIZE;
    }

    directmap_end = biosmem_directmap_end();

    if (directmap_end > (VM_MAX_DIRECTMAP_ADDRESS - VM_MIN_DIRECTMAP_ADDRESS)) {
        boot_panic(pmap_panic_directmap_msg);
    }

    va = VM_MIN_DIRECTMAP_ADDRESS;
    pa = 0;

    for (i = 0; i < directmap_end; i += pgsize) {
        pmap_boot_enter(root_ptp, va, pa, pgsize);
        va += pgsize;
        pa += pgsize;
    }

#ifdef __LP64__
    /*
     * On 64-bits systems, the kernel isn't linked at addresses included
     * in the direct mapping, which requires the creation of an additional
     * mapping for it. See param.h for more details.
     */
    va = P2ALIGN((uintptr_t)&_init, pgsize);
    pa = BOOT_VTOP(va);
    size = vm_page_round((uintptr_t)&_end) - va;

    for (i = 0; i < size; i += pgsize) {
        pmap_boot_enter(root_ptp, va, pa, pgsize);
        va += pgsize;
        pa += pgsize;
    }
#endif /* __LP64__ */

    cpu_table = (void *)BOOT_VTOP((uintptr_t)&kernel_pmap_cpu_tables[0]);
    cpu_table->root_ptp_pa = (uintptr_t)root_ptp;

    return root_ptp;
}

pmap_pte_t * __boot
pmap_ap_setup_paging(void)
{
    struct pmap_cpu_table *cpu_table;
    struct pmap *pmap;
    unsigned long pgsize;

    pgsize = pmap_boot_get_pgsize();
    pmap_boot_enable_pgext(pgsize);

    pmap = (void *)BOOT_VTOP((uintptr_t)&kernel_pmap_store);
    cpu_table = (void *)BOOT_VTOP((uintptr_t)pmap->cpu_tables[boot_ap_id]);

#ifdef X15_X86_PAE
    return (void *)(uint32_t)cpu_table->root_ptp_pa;
#else /* X15_X86_PAE */
    return (void *)cpu_table->root_ptp_pa;
#endif /* X15_X86_PAE */
}

/*
 * Check address range with regard to physical map.
 */
#define pmap_assert_range(pmap, start, end)             \
MACRO_BEGIN                                             \
    assert((start) < (end));                            \
    assert(((end) <= VM_MIN_DIRECTMAP_ADDRESS)          \
           || ((start) >= VM_MAX_DIRECTMAP_ADDRESS));   \
                                                        \
    if ((pmap) == kernel_pmap) {                        \
        assert(((start) >= VM_MIN_KMEM_ADDRESS)         \
               && ((end) <= VM_MAX_KMEM_ADDRESS));      \
    } else {                                            \
        assert((end) <= VM_MAX_ADDRESS);                \
    }                                                   \
MACRO_END

static inline pmap_pte_t *
pmap_ptp_from_pa(phys_addr_t pa)
{
    uintptr_t va;

    va = vm_page_direct_va(pa);
    return (pmap_pte_t *)va;
}

static void
pmap_ptp_clear(pmap_pte_t *ptp)
{
    memset(ptp, 0, PAGE_SIZE);
}

static inline void
pmap_pte_set(pmap_pte_t *pte, phys_addr_t pa, pmap_pte_t pte_bits,
             const struct pmap_pt_level *pt_level)
{
    *pte = ((pa & PMAP_PA_MASK) | PMAP_PTE_P | pte_bits) & pt_level->mask;
}

static inline void
pmap_pte_clear(pmap_pte_t *pte)
{
    *pte = 0;
}

static inline int
pmap_pte_valid(pmap_pte_t pte)
{
    return (pte != 0);
}

static inline int
pmap_pte_large(pmap_pte_t pte)
{
    return ((pte & PMAP_PTE_PS) != 0);
}

static inline pmap_pte_t *
pmap_pte_next(pmap_pte_t pte)
{
    assert(pmap_pte_valid(pte));
    return pmap_ptp_from_pa(pte & PMAP_PA_MASK);
}

/*
 * Helper function for initialization procedures that require post-fixing
 * page properties.
 */
static void __init
pmap_walk_vas(uintptr_t start, uintptr_t end, pmap_walk_fn_t walk_fn)
{
    const struct pmap_pt_level *pt_level;
    phys_addr_t root_ptp_pa, ptp_pa;
    pmap_pte_t *ptp, *pte;
    unsigned int index, level;
    uintptr_t va;

    assert(vm_page_aligned(start));
    assert(start < end);
#ifdef __LP64__
    assert((start < VM_MAX_ADDRESS) || (start >= VM_MIN_KERNEL_ADDRESS));
#endif /* __LP64__ */

    va = start;
    root_ptp_pa = kernel_pmap->cpu_tables[cpu_id()]->root_ptp_pa;

    do {
#ifdef __LP64__
        /* Handle long mode canonical form */
        if (va == VM_MAX_ADDRESS) {
            va = VM_MIN_KERNEL_ADDRESS;
        }
#endif /* __LP64__ */

        level = PMAP_NR_LEVELS - 1;
        ptp_pa = root_ptp_pa;
        ptp = pmap_ptp_from_pa(ptp_pa);

        for (;;) {
            pt_level = &pmap_pt_levels[level];
            index = pmap_pte_index(va, pt_level);
            pte = &ptp[index];

            if (!pmap_pte_valid(*pte)) {
                break;
            }

            walk_fn(ptp_pa, index, level);

            if ((level == 0) || pmap_pte_large(*pte)) {
                break;
            }

            level--;
            ptp_pa = *pte & PMAP_PA_MASK;
            ptp = pmap_ptp_from_pa(ptp_pa);
        }

        va = P2END(va, 1UL << pt_level->skip);
    } while ((va > start) && (va < end));
}

static void __init
pmap_setup_global_page(phys_addr_t ptp_pa, unsigned int index,
                       unsigned int level)
{
    pmap_pte_t *pte;

    pte = &pmap_ptp_from_pa(ptp_pa)[index];

    if ((level == 0) || pmap_pte_large(*pte)) {
        *pte |= PMAP_PTE_G;
    }
}

static void __init
pmap_setup_global_pages(void)
{
    pmap_walk_vas(VM_MIN_KERNEL_ADDRESS, VM_MAX_KERNEL_ADDRESS,
                  pmap_setup_global_page);
    pmap_pt_levels[0].mask |= PMAP_PTE_G;
    cpu_enable_global_pages();
}

static void
pmap_update_oplist_ctor(void *arg)
{
    struct pmap_update_oplist *oplist;

    oplist = arg;
    cpumap_zero(&oplist->cpumap);
    oplist->pmap = NULL;
    oplist->nr_ops = 0;
}

static int
pmap_update_oplist_create(struct pmap_update_oplist **oplistp)
{
    struct pmap_update_oplist *oplist;

    oplist = kmem_cache_alloc(&pmap_update_oplist_cache);

    if (oplist == NULL) {
        return ERROR_NOMEM;
    }

    *oplistp = oplist;
    return 0;
}

static void
pmap_update_oplist_destroy(void *arg)
{
    struct pmap_update_oplist *oplist;

    oplist = arg;
    kmem_cache_free(&pmap_update_oplist_cache, oplist);
}

static struct pmap_update_oplist *
pmap_update_oplist_get(void)
{
    struct pmap_update_oplist *oplist;

    oplist = thread_get_specific(pmap_oplist_tsd_key);
    assert(oplist != NULL);
    return oplist;
}

static int
pmap_update_oplist_prepare(struct pmap_update_oplist *oplist,
                           struct pmap *pmap)
{
    int error;

    if (oplist->pmap != pmap) {
        assert(oplist->pmap == NULL);
        oplist->pmap = pmap;
    } else if (oplist->nr_ops == ARRAY_SIZE(oplist->ops)) {
        error = pmap_update(pmap);
        oplist->pmap = pmap;
        return error;
    }

    return 0;
}

static struct pmap_update_op *
pmap_update_oplist_prev_op(struct pmap_update_oplist *oplist)
{
    if (oplist->nr_ops == 0) {
        return NULL;
    }

    return &oplist->ops[oplist->nr_ops - 1];
}

static struct pmap_update_op *
pmap_update_oplist_prepare_op(struct pmap_update_oplist *oplist)
{
    assert(oplist->nr_ops < ARRAY_SIZE(oplist->ops));
    return &oplist->ops[oplist->nr_ops];
}

static void
pmap_update_oplist_finish_op(struct pmap_update_oplist *oplist)
{
    struct pmap_update_op *op;

    assert(oplist->nr_ops < ARRAY_SIZE(oplist->ops));
    op = &oplist->ops[oplist->nr_ops];
    cpumap_or(&oplist->cpumap, &op->cpumap);
    oplist->nr_ops++;
}

static unsigned int
pmap_update_oplist_count_mappings(const struct pmap_update_oplist *oplist,
                                  unsigned int cpu)
{
    const struct pmap_update_op *op;
    unsigned int i, nr_mappings;

    nr_mappings = 0;

    for (i = 0; i < oplist->nr_ops; i++) {
        op = &oplist->ops[i];

        if (!cpumap_test(&op->cpumap, cpu)) {
            continue;
        }

        switch (op->operation) {
        case PMAP_UPDATE_OP_ENTER:
            nr_mappings++;
            break;
        case PMAP_UPDATE_OP_REMOVE:
            nr_mappings += (op->remove_args.end - op->remove_args.start)
                           / PAGE_SIZE;
            break;
        case PMAP_UPDATE_OP_PROTECT:
            nr_mappings += (op->protect_args.end - op->protect_args.start)
                           / PAGE_SIZE;
            break;
        default:
            assert(!"invalid update operation");
        }
    }

    assert(nr_mappings != 0);
    return nr_mappings;
}

static void
pmap_update_request_array_init(struct pmap_update_request_array *array)
{
    struct pmap_update_request *request;
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(array->requests); i++) {
        request = &array->requests[i];
        spinlock_init(&request->lock);
    }

    mutex_init(&array->lock);
}

static struct pmap_update_request_array *
pmap_update_request_array_acquire(void)
{
    struct pmap_update_request_array *array;

    thread_pin();
    array = cpu_local_ptr(pmap_update_request_array);
    mutex_lock(&array->lock);
    return array;
}

static void
pmap_update_request_array_release(struct pmap_update_request_array *array)
{
    mutex_unlock(&array->lock);
    thread_unpin();
}

static void __init
pmap_syncer_init(struct pmap_syncer *syncer, unsigned int cpu)
{
    char name[SYSCNT_NAME_SIZE];
    struct pmap_update_queue *queue;

    queue = &syncer->queue;
    spinlock_init(&queue->lock);
    list_init(&queue->requests);
    snprintf(name, sizeof(name), "pmap_updates/%u", cpu);
    syscnt_register(&syncer->sc_updates, name);
    snprintf(name, sizeof(name), "pmap_update_enters/%u", cpu);
    syscnt_register(&syncer->sc_update_enters, name);
    snprintf(name, sizeof(name), "pmap_update_removes/%u", cpu);
    syscnt_register(&syncer->sc_update_removes, name);
    snprintf(name, sizeof(name), "pmap_update_protects/%u", cpu);
    syscnt_register(&syncer->sc_update_protects, name);
}

void __init
pmap_bootstrap(void)
{
    struct pmap_cpu_table *cpu_table;
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(kernel_pmap->cpu_tables); i++) {
        cpu_table = &kernel_pmap_cpu_tables[i];
        kernel_pmap->cpu_tables[i] = cpu_table;
    }

    cpu_local_assign(pmap_current_ptr, kernel_pmap);

    pmap_prot_table[VM_PROT_NONE] = 0;
    pmap_prot_table[VM_PROT_READ] = 0;
    pmap_prot_table[VM_PROT_WRITE] = PMAP_PTE_RW;
    pmap_prot_table[VM_PROT_WRITE | VM_PROT_READ] = PMAP_PTE_RW;
    pmap_prot_table[VM_PROT_EXECUTE] = 0;
    pmap_prot_table[VM_PROT_EXECUTE | VM_PROT_READ] = 0;
    pmap_prot_table[VM_PROT_EXECUTE | VM_PROT_WRITE] = PMAP_PTE_RW;
    pmap_prot_table[VM_PROT_ALL] = PMAP_PTE_RW;

    pmap_update_request_array_init(cpu_local_ptr(pmap_update_request_array));

    pmap_syncer_init(cpu_local_ptr(pmap_syncer), 0);

    pmap_update_oplist_ctor(&pmap_booter_oplist);
    thread_key_create(&pmap_oplist_tsd_key, pmap_update_oplist_destroy);
    thread_set_specific(pmap_oplist_tsd_key, &pmap_booter_oplist);

    cpumap_zero(&pmap_booter_cpumap);
    cpumap_set(&pmap_booter_cpumap, 0);

    if (cpu_has_global_pages()) {
        pmap_setup_global_pages();
    }
}

void __init
pmap_ap_bootstrap(void)
{
    cpu_local_assign(pmap_current_ptr, kernel_pmap);

    if (cpu_has_global_pages()) {
        cpu_enable_global_pages();
    } else {
        cpu_tlb_flush();
    }
}

static void __init
pmap_setup_set_ptp_type(phys_addr_t ptp_pa, unsigned int index,
                        unsigned int level)
{
    struct vm_page *page;

    (void)index;

    if (level == 0) {
        return;
    }

    page = vm_page_lookup(ptp_pa);
    assert(page != NULL);

    if (vm_page_type(page) != VM_PAGE_PMAP) {
        assert(vm_page_type(page) == VM_PAGE_RESERVED);
        vm_page_set_type(page, 0, VM_PAGE_PMAP);
    }
}

static void __init
pmap_setup_fix_ptps(void)
{
    pmap_walk_vas(VM_MIN_ADDRESS, VM_MAX_KERNEL_ADDRESS,
                  pmap_setup_set_ptp_type);
}

void __init
pmap_setup(void)
{
    pmap_setup_fix_ptps();
    kmem_cache_init(&pmap_cache, "pmap", sizeof(struct pmap), 0, NULL, 0);
    kmem_cache_init(&pmap_update_oplist_cache, "pmap_update_oplist",
                    sizeof(struct pmap_update_oplist), CPU_L1_SIZE,
                    pmap_update_oplist_ctor, 0);
}

static void __init
pmap_copy_cpu_table_page(const pmap_pte_t *sptp, unsigned int level,
                         struct vm_page *page)
{
    const struct pmap_pt_level *pt_level;
    pmap_pte_t *dptp;

    pt_level = &pmap_pt_levels[level];
    dptp = vm_page_direct_ptr(page);
    memcpy(dptp, sptp, pt_level->ptes_per_pt * sizeof(pmap_pte_t));
}

static void __init
pmap_copy_cpu_table_recursive(const pmap_pte_t *sptp, unsigned int level,
                              pmap_pte_t *dptp, uintptr_t start_va)
{
    const struct pmap_pt_level *pt_level;
    struct vm_page *page;
    phys_addr_t pa;
    unsigned int i;
    uintptr_t va;

    assert(level != 0);

    pt_level = &pmap_pt_levels[level];
    memset(dptp, 0, pt_level->ptes_per_pt * sizeof(pmap_pte_t));

    for (i = 0, va = start_va;
         i < pt_level->ptes_per_pt;
         i++, va = P2END(va, 1UL << pt_level->skip)) {
#ifdef __LP64__
        /* Handle long mode canonical form */
        if (va == VM_MAX_ADDRESS) {
            va = VM_MIN_KERNEL_ADDRESS;
        }
#endif /* __LP64__ */

        if (!pmap_pte_valid(sptp[i])) {
            continue;
        } else if (pmap_pte_large(sptp[i])) {
            dptp[i] = sptp[i];
            continue;
        }

        page = vm_page_alloc(0, VM_PAGE_SEL_DIRECTMAP, VM_PAGE_PMAP);

        if (page == NULL) {
            panic("pmap: unable to allocate page table page copy");
        }

        pa = vm_page_to_pa(page);
        dptp[i] = (sptp[i] & ~PMAP_PA_MASK) | (pa & PMAP_PA_MASK);

        if (((level - 1) == 0) || pmap_pte_large(sptp[i])) {
            pmap_copy_cpu_table_page(pmap_pte_next(sptp[i]), level - 1, page);
        } else {
            pmap_copy_cpu_table_recursive(pmap_pte_next(sptp[i]), level - 1,
                                          vm_page_direct_ptr(page), va);
        }
    }
}

static void __init
pmap_copy_cpu_table(unsigned int cpu)
{
    struct pmap_cpu_table *cpu_table;
    unsigned int level;
    const pmap_pte_t *sptp;
    pmap_pte_t *dptp;

    assert(cpu != 0);

    cpu_table = kernel_pmap->cpu_tables[cpu];
    level = PMAP_NR_LEVELS - 1;
    sptp = pmap_ptp_from_pa(kernel_pmap->cpu_tables[cpu_id()]->root_ptp_pa);

#ifdef X15_X86_PAE
    cpu_table->root_ptp_pa = BOOT_VTOP((uintptr_t)pmap_cpu_kpdpts[cpu]);
    dptp = pmap_ptp_from_pa(cpu_table->root_ptp_pa);
#else /* X15_X86_PAE */
    struct vm_page *page;

    page = vm_page_alloc(0, VM_PAGE_SEL_DIRECTMAP, VM_PAGE_PMAP);

    if (page == NULL) {
        panic("pmap: unable to allocate page table root page copy");
    }

    cpu_table->root_ptp_pa = vm_page_to_pa(page);
    dptp = vm_page_direct_ptr(page);
#endif /* X15_X86_PAE */

    pmap_copy_cpu_table_recursive(sptp, level, dptp, VM_MIN_ADDRESS);
}

void __init
pmap_mp_setup(void)
{
    char name[THREAD_NAME_SIZE];
    struct pmap_update_oplist *oplist;
    struct thread_attr attr;
    struct pmap_syncer *syncer;
    struct cpumap *cpumap;
    unsigned int cpu;
    int error;

    error = cpumap_create(&cpumap);

    if (error) {
        panic("pmap: unable to create syncer cpumap");
    }

    for (cpu = 1; cpu < cpu_count(); cpu++) {
        pmap_update_request_array_init(percpu_ptr(pmap_update_request_array,
                                                  cpu));
        pmap_syncer_init(percpu_ptr(pmap_syncer, cpu), cpu);
    }

    for (cpu = 0; cpu < cpu_count(); cpu++) {
        syncer = percpu_ptr(pmap_syncer, cpu);
        snprintf(name, sizeof(name), THREAD_KERNEL_PREFIX "pmap_sync/%u", cpu);
        cpumap_zero(cpumap);
        cpumap_set(cpumap, cpu);
        thread_attr_init(&attr, name);
        thread_attr_set_cpumap(&attr, cpumap);
        thread_attr_set_priority(&attr, THREAD_SCHED_FS_PRIO_MAX);
        error = thread_create(&syncer->thread, &attr, pmap_sync, syncer);

        if (error) {
            panic("pmap: unable to create syncer thread");
        }

        oplist = thread_tsd_get(syncer->thread, pmap_oplist_tsd_key);
        thread_tsd_set(syncer->thread, pmap_oplist_tsd_key, NULL);
        kmem_cache_free(&pmap_update_oplist_cache, oplist);
    }

    cpumap_destroy(cpumap);

    for (cpu = 1; cpu < cpu_count(); cpu++) {
        pmap_copy_cpu_table(cpu);
    }

    pmap_do_remote_updates = 1;
}

int
pmap_thread_init(struct thread *thread)
{
    struct pmap_update_oplist *oplist;
    int error;

    error = pmap_update_oplist_create(&oplist);

    if (error) {
        return error;
    }

    thread_tsd_set(thread, pmap_oplist_tsd_key, oplist);
    return 0;
}

int
pmap_kextract(uintptr_t va, phys_addr_t *pap)
{
    const struct pmap_pt_level *pt_level;
    pmap_pte_t *ptp, *pte;
    unsigned int level;

    level = PMAP_NR_LEVELS - 1;
    ptp = pmap_ptp_from_pa(kernel_pmap->cpu_tables[cpu_id()]->root_ptp_pa);

    for (;;) {
        pt_level = &pmap_pt_levels[level];
        pte = &ptp[pmap_pte_index(va, pt_level)];

        if (!pmap_pte_valid(*pte)) {
            return ERROR_FAULT;
        }

        if ((level == 0) || pmap_pte_large(*pte)) {
            break;
        }

        level--;
        ptp = pmap_pte_next(*pte);
    }

    *pap = (*pte & PMAP_PA_MASK);
    return 0;
}

int
pmap_create(struct pmap **pmapp)
{
    struct pmap *pmap;
    unsigned int i;

    pmap = kmem_cache_alloc(&pmap_cache);

    if (pmap == NULL) {
        return ERROR_NOMEM;
    }

    for (i = 0; i < ARRAY_SIZE(pmap->cpu_tables); i++) {
        pmap->cpu_tables[i] = NULL;
    }

    *pmapp = pmap;
    return 0;
}

static int
pmap_enter_local(struct pmap *pmap, uintptr_t va, phys_addr_t pa,
                 int prot, int flags)
{
    const struct pmap_pt_level *pt_level;
    struct vm_page *page;
    phys_addr_t ptp_pa;
    pmap_pte_t *ptp, *pte, pte_bits;
    unsigned int level;

    /* TODO Page attributes */
    (void)flags;

    pte_bits = PMAP_PTE_RW;

    if (pmap != kernel_pmap) {
        pte_bits |= PMAP_PTE_US;
    }

    level = PMAP_NR_LEVELS - 1;
    ptp = pmap_ptp_from_pa(pmap->cpu_tables[cpu_id()]->root_ptp_pa);

    for (;;) {
        pt_level = &pmap_pt_levels[level];
        pte = &ptp[pmap_pte_index(va, pt_level)];

        if (level == 0) {
            break;
        }

        if (pmap_pte_valid(*pte)) {
            ptp = pmap_pte_next(*pte);
        } else {
            page = vm_page_alloc(0, VM_PAGE_SEL_DIRECTMAP, VM_PAGE_PMAP);

            if (page == NULL) {
                printk("pmap: warning: page table page allocation failure\n");
                return ERROR_NOMEM;
            }

            ptp_pa = vm_page_to_pa(page);
            ptp = pmap_ptp_from_pa(ptp_pa);
            pmap_ptp_clear(ptp);
            pmap_pte_set(pte, ptp_pa, pte_bits, pt_level);
        }

        level--;
    }

    assert(!pmap_pte_valid(*pte));
    pte_bits = ((pmap == kernel_pmap) ? PMAP_PTE_G : PMAP_PTE_US)
               | pmap_prot_table[prot & VM_PROT_ALL];
    pmap_pte_set(pte, pa, pte_bits, pt_level);
    return 0;
}

int
pmap_enter(struct pmap *pmap, uintptr_t va, phys_addr_t pa,
           int prot, int flags)
{
    struct pmap_update_oplist *oplist;
    struct pmap_update_op *op;
    int error;

    va = vm_page_trunc(va);
    pa = vm_page_trunc(pa);
    pmap_assert_range(pmap, va, va + PAGE_SIZE);

    oplist = pmap_update_oplist_get();
    error = pmap_update_oplist_prepare(oplist, pmap);

    if (error) {
        return error;
    }

    op = pmap_update_oplist_prepare_op(oplist);

    if (flags & PMAP_PEF_GLOBAL) {
        cpumap_copy(&op->cpumap, cpumap_all());
    } else {
        cpumap_zero(&op->cpumap);
        cpumap_set(&op->cpumap, cpu_id());
    }

    op->operation = PMAP_UPDATE_OP_ENTER;
    op->enter_args.va = va;
    op->enter_args.pa = pa;
    op->enter_args.prot = prot;
    op->enter_args.flags = flags & ~PMAP_PEF_GLOBAL;
    pmap_update_oplist_finish_op(oplist);
    return 0;
}

static void
pmap_remove_local_single(struct pmap *pmap, uintptr_t va)
{
    const struct pmap_pt_level *pt_level;
    pmap_pte_t *ptp, *pte;
    unsigned int level;

    level = PMAP_NR_LEVELS - 1;
    ptp = pmap_ptp_from_pa(pmap->cpu_tables[cpu_id()]->root_ptp_pa);

    for (;;) {
        pt_level = &pmap_pt_levels[level];
        pte = &ptp[pmap_pte_index(va, pt_level)];

        if (!pmap_pte_valid(*pte)) {
            return;
        }

        if (level == 0) {
            break;
        }

        level--;
        ptp = pmap_pte_next(*pte);
    }

    pmap_pte_clear(pte);
}

static void
pmap_remove_local(struct pmap *pmap, uintptr_t start, uintptr_t end)
{
    while (start < end) {
        pmap_remove_local_single(pmap, start);
        start += PAGE_SIZE;
    }
}

int
pmap_remove(struct pmap *pmap, uintptr_t va, const struct cpumap *cpumap)
{
    struct pmap_update_oplist *oplist;
    struct pmap_update_op *op;
    int error;

    va = vm_page_trunc(va);
    pmap_assert_range(pmap, va, va + PAGE_SIZE);

    oplist = pmap_update_oplist_get();
    error = pmap_update_oplist_prepare(oplist, pmap);

    if (error) {
        return error;
    }

    /* Attempt naive merge with previous operation */
    op = pmap_update_oplist_prev_op(oplist);

    if ((op != NULL)
        && (op->operation == PMAP_UPDATE_OP_REMOVE)
        && (op->remove_args.end == va)
        && (cpumap_cmp(&op->cpumap, cpumap) == 0)) {
        op->remove_args.end = va + PAGE_SIZE;
        return 0;
    }

    op = pmap_update_oplist_prepare_op(oplist);
    cpumap_copy(&op->cpumap, cpumap);
    op->operation = PMAP_UPDATE_OP_REMOVE;
    op->remove_args.start = va;
    op->remove_args.end = va + PAGE_SIZE;
    pmap_update_oplist_finish_op(oplist);
    return 0;
}

static void
pmap_protect_local(struct pmap *pmap, uintptr_t start,
                   uintptr_t end, int prot)
{
    (void)pmap;
    (void)start;
    (void)end;
    (void)prot;

    /* TODO Implement */
    panic("pmap: pmap_protect not implemented");
}

int
pmap_protect(struct pmap *pmap, uintptr_t va, int prot,
             const struct cpumap *cpumap)
{
    struct pmap_update_oplist *oplist;
    struct pmap_update_op *op;
    int error;

    va = vm_page_trunc(va);
    pmap_assert_range(pmap, va, va + PAGE_SIZE);

    oplist = pmap_update_oplist_get();
    error = pmap_update_oplist_prepare(oplist, pmap);

    if (error) {
        return error;
    }

    /* Attempt naive merge with previous operation */
    op = pmap_update_oplist_prev_op(oplist);

    if ((op != NULL)
        && (op->operation == PMAP_UPDATE_OP_PROTECT)
        && (op->protect_args.end == va)
        && (op->protect_args.prot == prot)
        && (cpumap_cmp(&op->cpumap, cpumap) == 0)) {
        op->protect_args.end = va + PAGE_SIZE;
        return 0;
    }

    op = pmap_update_oplist_prepare_op(oplist);
    cpumap_copy(&op->cpumap, cpumap);
    op->operation = PMAP_UPDATE_OP_PROTECT;
    op->protect_args.start = va;
    op->protect_args.end = va + PAGE_SIZE;
    op->protect_args.prot = prot;
    pmap_update_oplist_finish_op(oplist);
    return 0;
}

static void
pmap_flush_tlb(struct pmap *pmap, uintptr_t start, uintptr_t end)
{
    if ((pmap != pmap_current()) && (pmap != kernel_pmap)) {
        return;
    }

    while (start < end) {
        cpu_tlb_flush_va(start);
        start += PAGE_SIZE;
    }
}

static void
pmap_flush_tlb_all(struct pmap *pmap)
{
    if ((pmap != pmap_current()) && (pmap != kernel_pmap)) {
        return;
    }

    if (pmap == kernel_pmap) {
        cpu_tlb_flush_all();
    } else {
        cpu_tlb_flush();
    }
}

static int
pmap_update_enter(struct pmap *pmap, int flush,
                  const struct pmap_update_enter_args *args)
{
    int error;

    error = pmap_enter_local(pmap, args->va, args->pa, args->prot, args->flags);

    if (error) {
        return error;
    }

    if (flush) {
        pmap_flush_tlb(pmap, args->va, args->va + PAGE_SIZE);
    }

    return 0;
}

static void
pmap_update_remove(struct pmap *pmap, int flush,
                   const struct pmap_update_remove_args *args)
{
    pmap_remove_local(pmap, args->start, args->end);

    if (flush) {
        pmap_flush_tlb(pmap, args->start, args->end);
    }
}

static void
pmap_update_protect(struct pmap *pmap, int flush,
                    const struct pmap_update_protect_args *args)
{
    pmap_protect_local(pmap, args->start, args->end, args->prot);

    if (flush) {
        pmap_flush_tlb(pmap, args->start, args->end);
    }
}

static int
pmap_update_local(const struct pmap_update_oplist *oplist,
                  unsigned int nr_mappings)
{
    const struct pmap_update_op *op;
    struct pmap_syncer *syncer;
    int error, global_tlb_flush;
    unsigned int i;

    syncer = cpu_local_ptr(pmap_syncer);
    syscnt_inc(&syncer->sc_updates);
    global_tlb_flush = (nr_mappings > PMAP_UPDATE_MAX_MAPPINGS);
    error = 0;

    for (i = 0; i < oplist->nr_ops; i++) {
        op = &oplist->ops[i];

        if (!cpumap_test(&op->cpumap, cpu_id())) {
            continue;
        }

        switch (op->operation) {
        case PMAP_UPDATE_OP_ENTER:
            syscnt_inc(&syncer->sc_update_enters);
            error = pmap_update_enter(oplist->pmap, !global_tlb_flush,
                                      &op->enter_args);
            break;
        case PMAP_UPDATE_OP_REMOVE:
            syscnt_inc(&syncer->sc_update_removes);
            pmap_update_remove(oplist->pmap, !global_tlb_flush,
                               &op->remove_args);
            break;
        case PMAP_UPDATE_OP_PROTECT:
            syscnt_inc(&syncer->sc_update_protects);
            pmap_update_protect(oplist->pmap, !global_tlb_flush,
                                &op->protect_args);
            break;
        default:
            assert(!"invalid update operation");
        }

        if (error) {
            return error;
        }
    }

    if (global_tlb_flush) {
        pmap_flush_tlb_all(oplist->pmap);
    }

    return 0;
}

int
pmap_update(struct pmap *pmap)
{
    struct pmap_update_oplist *oplist;
    struct pmap_update_request_array *array;
    struct pmap_update_request *request;
    struct pmap_update_queue *queue;
    struct pmap_syncer *syncer;
    unsigned int nr_mappings;
    int error, cpu;

    oplist = pmap_update_oplist_get();

    if (pmap != oplist->pmap) {
        /* Make sure pmap_update() is called before manipulating another pmap */
        assert(oplist->pmap == NULL);
        return 0;
    }

    assert(oplist->nr_ops != 0);

    if (!pmap_do_remote_updates) {
        nr_mappings = pmap_update_oplist_count_mappings(oplist, cpu_id());
        error = pmap_update_local(oplist, nr_mappings);
        goto out;
    }

    error = 0;

    array = pmap_update_request_array_acquire();

    cpumap_for_each(&oplist->cpumap, cpu) {
        syncer = percpu_ptr(pmap_syncer, cpu);
        queue = &syncer->queue;
        request = &array->requests[cpu];
        request->sender = thread_self();
        request->oplist = oplist;
        request->nr_mappings = pmap_update_oplist_count_mappings(oplist, cpu);
        request->done = 0;
        request->error = 0;

        spinlock_lock(&queue->lock);
        list_insert_tail(&queue->requests, &request->node);
        thread_wakeup(syncer->thread);
        spinlock_unlock(&queue->lock);
    }

    cpumap_for_each(&oplist->cpumap, cpu) {
        request = &array->requests[cpu];

        spinlock_lock(&request->lock);

        while (!request->done) {
            thread_sleep(&request->lock, request, "pmaprq");
        }

        if (!error && request->error) {
            error = request->error;
        }

        spinlock_unlock(&request->lock);
    }

    pmap_update_request_array_release(array);

out:
    cpumap_zero(&oplist->cpumap);
    oplist->pmap = NULL;
    oplist->nr_ops = 0;
    return error;
}

static void
pmap_sync(void *arg)
{
    struct pmap_update_queue *queue;
    struct pmap_update_request *request;
    struct pmap_syncer *self;
    int error;

    self = arg;
    queue = &self->queue;

    for (;;) {
        spinlock_lock(&queue->lock);

        while (list_empty(&queue->requests)) {
            thread_sleep(&queue->lock, queue, "pmapq");
        }

        request = list_first_entry(&queue->requests,
                                   struct pmap_update_request, node);
        list_remove(&request->node);

        spinlock_unlock(&queue->lock);

        error = pmap_update_local(request->oplist, request->nr_mappings);

        spinlock_lock(&request->lock);
        request->done = 1;
        request->error = error;
        thread_wakeup(request->sender);
        spinlock_unlock(&request->lock);
    }
}

void
pmap_load(struct pmap *pmap)
{
    struct pmap_cpu_table *cpu_table;

    assert(!cpu_intr_enabled());
    assert(!thread_preempt_enabled());

    if (pmap_current() == pmap) {
        return;
    }

    /* TODO Lazy TLB invalidation */

    cpu_local_assign(pmap_current_ptr, pmap);

    /* TODO Implement per-CPU page tables for non-kernel pmaps */
    cpu_table = pmap->cpu_tables[cpu_id()];

    cpu_set_cr3(cpu_table->root_ptp_pa);
}
