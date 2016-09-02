/*
 * Copyright (c) 2010-2014 Richard Braun.
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

#include <kern/assert.h>
#include <kern/condition.h>
#include <kern/cpumap.h>
#include <kern/error.h>
#include <kern/evcnt.h>
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
#include <kern/stddef.h>
#include <kern/string.h>
#include <kern/thread.h>
#include <kern/types.h>
#include <machine/biosmem.h>
#include <machine/boot.h>
#include <machine/cpu.h>
#include <machine/lapic.h>
#include <machine/pmap.h>
#include <machine/trap.h>
#include <vm/vm_kmem.h>
#include <vm/vm_page.h>
#include <vm/vm_prot.h>

/*
 * Properties of a page translation level.
 */
struct pmap_pt_level {
    unsigned int skip;
    unsigned int bits;
    unsigned int ptes_per_ptp;
    pmap_pte_t mask;
};

/*
 * Table of page translation properties.
 */
static struct pmap_pt_level pmap_pt_levels[] __read_mostly = {
    { PMAP_L0_SKIP, PMAP_L0_BITS, PMAP_L0_PTES_PER_PTP, PMAP_L0_MASK },
    { PMAP_L1_SKIP, PMAP_L1_BITS, PMAP_L1_PTES_PER_PTP, PMAP_L1_MASK },
#if PMAP_NR_LEVELS == 4
    { PMAP_L2_SKIP, PMAP_L2_BITS, PMAP_L2_PTES_PER_PTP, PMAP_L2_MASK },
    { PMAP_L3_SKIP, PMAP_L3_BITS, PMAP_L3_PTES_PER_PTP, PMAP_L3_MASK },
#endif /* PMAP_NR_LEVELS == 4 */
};

/*
 * Per-CPU page tables.
 */
struct pmap_cpu_table {
    struct mutex lock;
    struct list node;
    phys_addr_t root_ptp_pa;

#ifdef X86_PAE
    pmap_pte_t *pdpt;

    /* The page-directory-pointer base is always 32-bits wide */
    unsigned long pdpt_pa;
#endif /* X86_PAE */
};

struct pmap {
    struct pmap_cpu_table *cpu_tables[MAX_CPUS];
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
static struct pmap_cpu_table kernel_pmap_cpu_tables[MAX_CPUS] __read_mostly;

struct pmap *pmap_current_ptr __percpu;

#ifdef X86_PAE

/*
 * Alignment required on page directory pointer tables.
 */
#define PMAP_PDPT_ALIGN 32

/*
 * "Hidden" kernel root page tables for PAE mode.
 */
static pmap_pte_t pmap_cpu_kpdpts[MAX_CPUS][PMAP_NR_RPTPS] __read_mostly
    __aligned(PMAP_PDPT_ALIGN);

#endif /* X86_PAE */

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
    unsigned long va;
    phys_addr_t pa;
    int prot;
    int flags;
};

struct pmap_update_remove_args {
    unsigned long start;
    unsigned long end;
};

struct pmap_update_protect_args {
    unsigned long start;
    unsigned long end;
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
    struct mutex lock;
    struct condition cond;
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
    struct evcnt ev_update;
    struct evcnt ev_update_enter;
    struct evcnt ev_update_remove;
    struct evcnt ev_update_protect;
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
    struct mutex lock;
    struct condition cond;
    const struct pmap_update_oplist *oplist;
    unsigned int nr_mappings;
    int done;
} __aligned(CPU_L1_SIZE);

/*
 * Per processor array of requests.
 *
 * When an operation list is to be applied, the thread triggering the update
 * acquires the processor-local array of requests and uses it to queue requests
 * on remote processors.
 */
struct pmap_update_request_array {
    struct pmap_update_request requests[MAX_CPUS];
    struct mutex lock;
};

static struct pmap_update_request_array pmap_update_request_array __percpu;

static int pmap_do_remote_updates __read_mostly;

static struct kmem_cache pmap_cache;

#ifdef X86_PAE
static char pmap_panic_no_pae[] __bootdata
    = "pmap: PAE not supported";
#endif /* X86_PAE */
static char pmap_panic_inval_msg[] __bootdata
    = "pmap: invalid physical address";
static char pmap_panic_directmap_msg[] __bootdata
    = "pmap: invalid direct physical mapping";

static __always_inline unsigned long
pmap_pte_index(unsigned long va, const struct pmap_pt_level *pt_level)
{
    return ((va >> pt_level->skip) & ((1UL << pt_level->bits) - 1));
}

static void __boot
pmap_boot_enter(pmap_pte_t *root_ptp, unsigned long va, phys_addr_t pa,
                unsigned long pgsize)
{
    const struct pmap_pt_level *pt_level, *pt_levels;
    pmap_pte_t *pt, *ptp, *pte, bits;
    unsigned int level, last_level;

    if (pa != (pa & PMAP_PA_MASK))
        boot_panic(pmap_panic_inval_msg);

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

    pt_levels = (void *)BOOT_VTOP((unsigned long)pmap_pt_levels);
    pt = root_ptp;

    for (level = PMAP_NR_LEVELS - 1; level != last_level; level--) {
        pt_level = &pt_levels[level];
        pte = &pt[pmap_pte_index(va, pt_level)];

        if (*pte != 0)
            ptp = (void *)(unsigned long)(*pte & PMAP_PA_MASK);
        else {
            ptp = biosmem_bootalloc(1);
            *pte = ((unsigned long)ptp | PMAP_PTE_RW | PMAP_PTE_P)
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

    if (eax <= 0x80000000)
        goto out;

    eax = 0x80000001;
    cpu_cpuid(&eax, &ebx, &ecx, &edx);

    if (edx & CPU_FEATURE4_1GP)
        return (1 << PMAP_L2_SKIP);

out:
    return (1 << PMAP_L1_SKIP);
#else /* __LP64__ */
    eax = 0;
    cpu_cpuid(&eax, &ebx, &ecx, &edx);

    if (eax == 0)
        goto out;

    eax = 1;
    cpu_cpuid(&eax, &ebx, &ecx, &edx);

#ifdef X86_PAE
    if (!(edx & CPU_FEATURE2_PAE))
        boot_panic(pmap_panic_no_pae);

    return (1 << PMAP_L1_SKIP);
#else /* X86_PAE */
    if (edx & CPU_FEATURE2_PSE)
        return (1 << PMAP_L1_SKIP);
#endif /* X86_PAE */

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
    if (pgsize == PAGE_SIZE)
        return;

    /*
     * On 64-bits systems, PAE is already enabled.
     *
     * See the boot module.
     */
#ifdef X86_PAE
    cpu_enable_pae();
#else /* X86_PAE */
    cpu_enable_pse();
#endif /* X86_PAE */
}
#endif /* __LP64__ */

pmap_pte_t * __boot
pmap_setup_paging(void)
{
    struct pmap_cpu_table *cpu_table;
    phys_addr_t pa, directmap_end;
    unsigned long i, va, size, pgsize;
    pmap_pte_t *root_ptp;

    /* Use large pages for the direct physical mapping when possible */
    pgsize = pmap_boot_get_pgsize();
    pmap_boot_enable_pgext(pgsize);

    /*
     * Create the initial mappings. The first is for the .boot section
     * and acts as the mandatory identity mapping. The second is the
     * direct physical mapping of physical memory.
     */

    root_ptp = biosmem_bootalloc(PMAP_NR_RPTPS);

    va = vm_page_trunc((unsigned long)&_boot);
    pa = va;
    size = vm_page_round((unsigned long)&_eboot) - va;

    for (i = 0; i < size; i += PAGE_SIZE) {
        pmap_boot_enter(root_ptp, va, pa, PAGE_SIZE);
        va += PAGE_SIZE;
        pa += PAGE_SIZE;
    }

    directmap_end = biosmem_directmap_end();

    if (directmap_end > (VM_MAX_DIRECTMAP_ADDRESS - VM_MIN_DIRECTMAP_ADDRESS))
        boot_panic(pmap_panic_directmap_msg);

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
    va = P2ALIGN((unsigned long)&_init, pgsize);
    pa = BOOT_VTOP(va);
    size = vm_page_round((unsigned long)&_end) - va;

    for (i = 0; i < size; i += pgsize) {
        pmap_boot_enter(root_ptp, va, pa, pgsize);
        va += pgsize;
        pa += pgsize;
    }
#endif /* __LP64__ */

    cpu_table = (void *)BOOT_VTOP((unsigned long)&kernel_pmap_cpu_tables[0]);
    cpu_table->root_ptp_pa = (unsigned long)root_ptp;

#ifdef X86_PAE
    cpu_table->pdpt = pmap_cpu_kpdpts[0];
    cpu_table->pdpt_pa = BOOT_VTOP((unsigned long)pmap_cpu_kpdpts[0]);
    root_ptp = (void *)cpu_table->pdpt_pa;

    for (i = 0; i < PMAP_NR_RPTPS; i++)
        root_ptp[i] = (cpu_table->root_ptp_pa + (i * PAGE_SIZE)) | PMAP_PTE_P;
#endif /* X86_PAE */

    return root_ptp;
}

pmap_pte_t * __boot
pmap_ap_setup_paging(void)
{
    struct pmap_cpu_table *cpu_table;
    struct pmap *pmap;
    pmap_pte_t *root_ptp;
    unsigned long pgsize;

    pgsize = pmap_boot_get_pgsize();
    pmap_boot_enable_pgext(pgsize);

    pmap = (void *)BOOT_VTOP((unsigned long)&kernel_pmap_store);
    cpu_table = (void *)BOOT_VTOP((unsigned long)pmap->cpu_tables[boot_ap_id]);

#ifdef X86_PAE
    root_ptp = (void *)cpu_table->pdpt_pa;
#else /* X86_PAE */
    root_ptp = (void *)cpu_table->root_ptp_pa;
#endif /* X86_PAE */

    return root_ptp;
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
    if ((pmap) == kernel_pmap)                          \
        assert(((start) >= VM_MIN_KMEM_ADDRESS)         \
               && ((end) <= VM_MAX_KMEM_ADDRESS));      \
    else                                                \
        assert((end) <= VM_MAX_ADDRESS);                \
MACRO_END

static inline pmap_pte_t *
pmap_ptp_from_pa(phys_addr_t pa)
{
    unsigned long va;

    assert(vm_page_aligned(pa));
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
pmap_walk_vas(unsigned long start, unsigned long end, pmap_walk_fn_t walk_fn)
{
    const struct pmap_pt_level *pt_level;
    phys_addr_t root_ptp_pa, ptp_pa;
    pmap_pte_t *ptp, *pte;
    unsigned int index, level;
    unsigned long va;

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
        if (va == VM_MAX_ADDRESS)
            va = VM_MIN_KERNEL_ADDRESS;
#endif /* __LP64__ */

        level = PMAP_NR_LEVELS - 1;
        ptp_pa = root_ptp_pa;
        ptp = pmap_ptp_from_pa(ptp_pa);

        for (;;) {
            pt_level = &pmap_pt_levels[level];
            index = pmap_pte_index(va, pt_level);
            pte = &ptp[index];

            if (!pmap_pte_valid(*pte))
                break;

            walk_fn(ptp_pa, index, level);

            if ((level == 0) || pmap_pte_large(*pte))
                break;

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

    if ((level == 0) || pmap_pte_large(*pte))
        *pte |= PMAP_PTE_G;
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

    if (oplist == NULL)
        return ERROR_NOMEM;

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

static void
pmap_update_oplist_prepare(struct pmap_update_oplist *oplist,
                           struct pmap *pmap)
{
    if (oplist->pmap != pmap) {
        if (oplist->pmap != NULL)
            pmap_update(oplist->pmap);

        oplist->pmap = pmap;
    } else if (oplist->nr_ops == ARRAY_SIZE(oplist->ops)) {
        pmap_update(pmap);
        oplist->pmap = pmap;
    }
}

static struct pmap_update_op *
pmap_update_oplist_prev_op(struct pmap_update_oplist *oplist)
{
    if (oplist->nr_ops == 0)
        return NULL;

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

        if (!cpumap_test(&op->cpumap, cpu))
            continue;

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
        mutex_init(&request->lock);
        condition_init(&request->cond);
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
    char name[EVCNT_NAME_SIZE];
    struct pmap_update_queue *queue;

    queue = &syncer->queue;
    mutex_init(&queue->lock);
    condition_init(&queue->cond);
    list_init(&queue->requests);
    snprintf(name, sizeof(name), "pmap_update/%u", cpu);
    evcnt_register(&syncer->ev_update, name);
    snprintf(name, sizeof(name), "pmap_update_enter/%u", cpu);
    evcnt_register(&syncer->ev_update_enter, name);
    snprintf(name, sizeof(name), "pmap_update_remove/%u", cpu);
    evcnt_register(&syncer->ev_update_remove, name);
    snprintf(name, sizeof(name), "pmap_update_protect/%u", cpu);
    evcnt_register(&syncer->ev_update_protect, name);
}

void __init
pmap_bootstrap(void)
{
    struct pmap_cpu_table *cpu_table;
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(kernel_pmap->cpu_tables); i++) {
        cpu_table = &kernel_pmap_cpu_tables[i];
        kernel_pmap->cpu_tables[i] = cpu_table;
        mutex_init(&cpu_table->lock);
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

    if (cpu_has_global_pages())
        pmap_setup_global_pages();
}

void __init
pmap_ap_bootstrap(void)
{
    cpu_local_assign(pmap_current_ptr, kernel_pmap);

    if (cpu_has_global_pages())
        cpu_enable_global_pages();
    else
        cpu_tlb_flush();
}

static void __init
pmap_setup_set_ptp_type(phys_addr_t ptp_pa, unsigned int index,
                        unsigned int level)
{
    struct vm_page *page;

    (void)index;

    if (level == 0)
        return;

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
    memcpy(dptp, sptp, pt_level->ptes_per_ptp * sizeof(pmap_pte_t));
}

static void __init
pmap_copy_cpu_table_recursive(const pmap_pte_t *sptp, unsigned int level,
                              struct vm_page *page, unsigned long start_va)
{
    const struct pmap_pt_level *pt_level;
    pmap_pte_t *dptp;
    phys_addr_t pa;
    unsigned long va;
    unsigned int i;

    assert(level != 0);

    pt_level = &pmap_pt_levels[level];
    dptp = vm_page_direct_ptr(page);

    memset(dptp, 0, pt_level->ptes_per_ptp * sizeof(pmap_pte_t));

    for (i = 0, va = start_va;
         i < pt_level->ptes_per_ptp;
         i++, va = P2END(va, 1UL << pt_level->skip)) {
#ifdef __LP64__
        /* Handle long mode canonical form */
        if (va == VM_MAX_ADDRESS)
            va = VM_MIN_KERNEL_ADDRESS;
#endif /* __LP64__ */

        if (!pmap_pte_valid(sptp[i]))
            continue;
        else if (pmap_pte_large(sptp[i])) {
            dptp[i] = sptp[i];
            continue;
        }

        page = vm_page_alloc(0, VM_PAGE_SEL_DIRECTMAP, VM_PAGE_PMAP);
        assert(page != NULL);
        pa = vm_page_to_pa(page);
        dptp[i] = (sptp[i] & ~PMAP_PA_MASK) | (pa & PMAP_PA_MASK);

        if (((level - 1) == 0) || pmap_pte_large(sptp[i]))
            pmap_copy_cpu_table_page(pmap_pte_next(sptp[i]), level - 1, page);
        else
            pmap_copy_cpu_table_recursive(pmap_pte_next(sptp[i]),
                                          level - 1, page, va);
    }
}

static void __init
pmap_copy_cpu_table(unsigned int cpu)
{
    struct pmap_cpu_table *cpu_table;
    struct vm_page *page;
    unsigned int level;
    pmap_pte_t *ptp;

    cpu_table = kernel_pmap->cpu_tables[cpu];
    level = PMAP_NR_LEVELS - 1;
    ptp = pmap_ptp_from_pa(kernel_pmap->cpu_tables[cpu_id()]->root_ptp_pa);
    page = vm_page_alloc(PMAP_RPTP_ORDER, VM_PAGE_SEL_DIRECTMAP, VM_PAGE_PMAP);
    assert(page != NULL);
    pmap_copy_cpu_table_recursive(ptp, level, page, VM_MIN_ADDRESS);
    cpu_table->root_ptp_pa = vm_page_to_pa(page);

#ifdef X86_PAE
    unsigned int i;

    cpu_table->pdpt = pmap_cpu_kpdpts[cpu];
    cpu_table->pdpt_pa = BOOT_VTOP((unsigned long)pmap_cpu_kpdpts[cpu]);

    for (i = 0; i < PMAP_NR_RPTPS; i++)
        cpu_table->pdpt[i] = (cpu_table->root_ptp_pa + (i * PAGE_SIZE)) | PMAP_PTE_P;
#endif /* X86_PAE */
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

    if (error)
        panic("pmap: unable to create syncer cpumap");

    for (cpu = 1; cpu < cpu_count(); cpu++) {
        pmap_update_request_array_init(percpu_ptr(pmap_update_request_array,
                                                  cpu));
        pmap_syncer_init(percpu_ptr(pmap_syncer, cpu), cpu);
    }

    for (cpu = 0; cpu < cpu_count(); cpu++) {
        syncer = percpu_ptr(pmap_syncer, cpu);
        snprintf(name, sizeof(name), "x15_pmap_sync/%u", cpu);
        cpumap_zero(cpumap);
        cpumap_set(cpumap, cpu);
        thread_attr_init(&attr, name);
        thread_attr_set_cpumap(&attr, cpumap);
        thread_attr_set_policy(&attr, THREAD_SCHED_POLICY_FIFO);
        thread_attr_set_priority(&attr, THREAD_SCHED_RT_PRIO_MIN);
        error = thread_create(&syncer->thread, &attr, pmap_sync, syncer);

        if (error)
            panic("pmap: unable to create syncer thread");

        oplist = thread_tsd_get(syncer->thread, pmap_oplist_tsd_key);
        thread_tsd_set(syncer->thread, pmap_oplist_tsd_key, NULL);
        kmem_cache_free(&pmap_update_oplist_cache, oplist);
    }

    cpumap_destroy(cpumap);

    for (cpu = 1; cpu < cpu_count(); cpu++)
        pmap_copy_cpu_table(cpu);

    pmap_do_remote_updates = 1;
}

int
pmap_thread_init(struct thread *thread)
{
    struct pmap_update_oplist *oplist;
    int error;

    error = pmap_update_oplist_create(&oplist);

    if (error)
        return error;

    thread_tsd_set(thread, pmap_oplist_tsd_key, oplist);
    return 0;
}

int
pmap_kextract(unsigned long va, phys_addr_t *pap)
{
    const struct pmap_pt_level *pt_level;
    pmap_pte_t *ptp, *pte;
    unsigned int level;

    level = PMAP_NR_LEVELS - 1;
    ptp = pmap_ptp_from_pa(kernel_pmap->cpu_tables[cpu_id()]->root_ptp_pa);

    for (;;) {
        pt_level = &pmap_pt_levels[level];
        pte = &ptp[pmap_pte_index(va, pt_level)];

        if (!pmap_pte_valid(*pte))
            return ERROR_FAULT;

        if ((level == 0) || pmap_pte_large(*pte))
            break;

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

    if (pmap == NULL)
        return ERROR_NOMEM;

    for (i = 0; i < ARRAY_SIZE(pmap->cpu_tables); i++)
        pmap->cpu_tables[i] = NULL;

    *pmapp = pmap;
    return 0;
}

static void
pmap_enter_local(struct pmap *pmap, unsigned long va, phys_addr_t pa,
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

    if (pmap != kernel_pmap)
        pte_bits |= PMAP_PTE_US;

    level = PMAP_NR_LEVELS - 1;
    ptp = pmap_ptp_from_pa(pmap->cpu_tables[cpu_id()]->root_ptp_pa);

    for (;;) {
        pt_level = &pmap_pt_levels[level];
        pte = &ptp[pmap_pte_index(va, pt_level)];

        if (level == 0)
            break;

        if (pmap_pte_valid(*pte))
            ptp = pmap_pte_next(*pte);
        else {
            page = vm_page_alloc(0, VM_PAGE_SEL_DIRECTMAP, VM_PAGE_PMAP);
            assert(page != NULL);
            ptp_pa = vm_page_to_pa(page);
            ptp = pmap_ptp_from_pa(ptp_pa);
            pmap_ptp_clear(ptp);
            pmap_pte_set(pte, ptp_pa, pte_bits, pt_level);
        }

        level--;
    }

    pte_bits = ((pmap == kernel_pmap) ? PMAP_PTE_G : PMAP_PTE_US)
               | pmap_prot_table[prot & VM_PROT_ALL];
    pmap_pte_set(pte, pa, pte_bits, pt_level);
}

void
pmap_enter(struct pmap *pmap, unsigned long va, phys_addr_t pa,
           int prot, int flags)
{
    struct pmap_update_oplist *oplist;
    struct pmap_update_op *op;

    va = vm_page_trunc(va);
    pa = vm_page_trunc(pa);
    pmap_assert_range(pmap, va, va + PAGE_SIZE);

    oplist = pmap_update_oplist_get();
    pmap_update_oplist_prepare(oplist, pmap);
    op = pmap_update_oplist_prepare_op(oplist);

    if (flags & PMAP_PEF_GLOBAL)
        cpumap_copy(&op->cpumap, cpumap_all());
    else {
        cpumap_zero(&op->cpumap);
        cpumap_set(&op->cpumap, cpu_id());
    }

    op->operation = PMAP_UPDATE_OP_ENTER;
    op->enter_args.va = va;
    op->enter_args.pa = pa;
    op->enter_args.prot = prot;
    op->enter_args.flags = flags & ~PMAP_PEF_GLOBAL;
    pmap_update_oplist_finish_op(oplist);
}

static void
pmap_remove_local_single(struct pmap *pmap, unsigned long va)
{
    const struct pmap_pt_level *pt_level;
    pmap_pte_t *ptp, *pte;
    unsigned int level;

    level = PMAP_NR_LEVELS - 1;
    ptp = pmap_ptp_from_pa(pmap->cpu_tables[cpu_id()]->root_ptp_pa);

    for (;;) {
        pt_level = &pmap_pt_levels[level];
        pte = &ptp[pmap_pte_index(va, pt_level)];

        if (level == 0)
            break;

        level--;
        ptp = pmap_pte_next(*pte);
    }

    pmap_pte_clear(pte);
}

static void
pmap_remove_local(struct pmap *pmap, unsigned long start, unsigned long end)
{
    while (start < end) {
        pmap_remove_local_single(pmap, start);
        start += PAGE_SIZE;
    }
}

void
pmap_remove(struct pmap *pmap, unsigned long va, const struct cpumap *cpumap)
{
    struct pmap_update_oplist *oplist;
    struct pmap_update_op *op;

    va = vm_page_trunc(va);
    pmap_assert_range(pmap, va, va + PAGE_SIZE);

    oplist = pmap_update_oplist_get();
    pmap_update_oplist_prepare(oplist, pmap);

    /* Attempt naive merge with previous operation */
    op = pmap_update_oplist_prev_op(oplist);

    if ((op != NULL)
        && (op->operation == PMAP_UPDATE_OP_REMOVE)
        && (op->remove_args.end == va)
        && (cpumap_cmp(&op->cpumap, cpumap) == 0)) {
        op->remove_args.end = va + PAGE_SIZE;
        return;
    }

    op = pmap_update_oplist_prepare_op(oplist);
    cpumap_copy(&op->cpumap, cpumap);
    op->operation = PMAP_UPDATE_OP_REMOVE;
    op->remove_args.start = va;
    op->remove_args.end = va + PAGE_SIZE;
    pmap_update_oplist_finish_op(oplist);
}

static void
pmap_protect_local(struct pmap *pmap, unsigned long start,
                   unsigned long end, int prot)
{
    (void)pmap;
    (void)start;
    (void)end;
    (void)prot;

    /* TODO Implement */
    panic("pmap: pmap_protect not implemented");
}

void
pmap_protect(struct pmap *pmap, unsigned long va, int prot,
             const struct cpumap *cpumap)
{
    struct pmap_update_oplist *oplist;
    struct pmap_update_op *op;

    va = vm_page_trunc(va);
    pmap_assert_range(pmap, va, va + PAGE_SIZE);

    oplist = pmap_update_oplist_get();
    pmap_update_oplist_prepare(oplist, pmap);

    /* Attempt naive merge with previous operation */
    op = pmap_update_oplist_prev_op(oplist);

    if ((op != NULL)
        && (op->operation == PMAP_UPDATE_OP_PROTECT)
        && (op->protect_args.end == va)
        && (op->protect_args.prot == prot)
        && (cpumap_cmp(&op->cpumap, cpumap) == 0)) {
        op->protect_args.end = va + PAGE_SIZE;
        return;
    }

    op = pmap_update_oplist_prepare_op(oplist);
    cpumap_copy(&op->cpumap, cpumap);
    op->operation = PMAP_UPDATE_OP_PROTECT;
    op->protect_args.start = va;
    op->protect_args.end = va + PAGE_SIZE;
    op->protect_args.prot = prot;
    pmap_update_oplist_finish_op(oplist);
}

static void
pmap_flush_tlb(struct pmap *pmap, unsigned long start, unsigned long end)
{
    if ((pmap != pmap_current()) && (pmap != kernel_pmap))
        return;

    while (start < end) {
        cpu_tlb_flush_va(start);
        start += PAGE_SIZE;
    }
}

static void
pmap_flush_tlb_all(struct pmap *pmap)
{
    if ((pmap != pmap_current()) && (pmap != kernel_pmap))
        return;

    if (pmap == kernel_pmap)
        cpu_tlb_flush_all();
    else
        cpu_tlb_flush();
}

static void
pmap_update_enter(struct pmap *pmap, int flush,
                  const struct pmap_update_enter_args *args)
{
    pmap_enter_local(pmap, args->va, args->pa, args->prot, args->flags);

    if (flush)
        pmap_flush_tlb(pmap, args->va, args->va + PAGE_SIZE);
}

static void
pmap_update_remove(struct pmap *pmap, int flush,
                   const struct pmap_update_remove_args *args)
{
    pmap_remove_local(pmap, args->start, args->end);

    if (flush)
        pmap_flush_tlb(pmap, args->start, args->end);
}

static void
pmap_update_protect(struct pmap *pmap, int flush,
                    const struct pmap_update_protect_args *args)
{
    pmap_protect_local(pmap, args->start, args->end, args->prot);

    if (flush)
        pmap_flush_tlb(pmap, args->start, args->end);
}

static void
pmap_update_local(const struct pmap_update_oplist *oplist,
                  unsigned int nr_mappings)
{
    const struct pmap_update_op *op;
    struct pmap_syncer *syncer;
    int global_tlb_flush;
    unsigned int i;

    syncer = cpu_local_ptr(pmap_syncer);
    evcnt_inc(&syncer->ev_update);
    global_tlb_flush = (nr_mappings > PMAP_UPDATE_MAX_MAPPINGS);

    for (i = 0; i < oplist->nr_ops; i++) {
        op = &oplist->ops[i];

        if (!cpumap_test(&op->cpumap, cpu_id()))
            continue;

        switch (op->operation) {
        case PMAP_UPDATE_OP_ENTER:
            evcnt_inc(&syncer->ev_update_enter);
            pmap_update_enter(oplist->pmap, !global_tlb_flush,
                              &op->enter_args);
            break;
        case PMAP_UPDATE_OP_REMOVE:
            evcnt_inc(&syncer->ev_update_remove);
            pmap_update_remove(oplist->pmap, !global_tlb_flush,
                               &op->remove_args);
            break;
        case PMAP_UPDATE_OP_PROTECT:
            evcnt_inc(&syncer->ev_update_protect);
            pmap_update_protect(oplist->pmap, !global_tlb_flush,
                                &op->protect_args);
            break;
        default:
            assert(!"invalid update operation");
        }
    }

    if (global_tlb_flush)
        pmap_flush_tlb_all(oplist->pmap);
}

void
pmap_update(struct pmap *pmap)
{
    struct pmap_update_oplist *oplist;
    struct pmap_update_request_array *array;
    struct pmap_update_request *request;
    struct pmap_update_queue *queue;
    struct pmap_syncer *syncer;
    unsigned int nr_mappings;
    int cpu;

    oplist = pmap_update_oplist_get();

    if (pmap != oplist->pmap)
        return;

    assert(oplist->nr_ops != 0);

    if (!pmap_do_remote_updates) {
        nr_mappings = pmap_update_oplist_count_mappings(oplist, cpu_id());
        pmap_update_local(oplist, nr_mappings);
        goto out;
    }

    array = pmap_update_request_array_acquire();

    cpumap_for_each(&oplist->cpumap, cpu) {
        syncer = percpu_ptr(pmap_syncer, cpu);
        queue = &syncer->queue;
        request = &array->requests[cpu];
        request->oplist = oplist;
        request->nr_mappings = pmap_update_oplist_count_mappings(oplist, cpu);
        request->done = 0;

        mutex_lock(&queue->lock);
        list_insert_tail(&queue->requests, &request->node);
        condition_signal(&queue->cond);
        mutex_unlock(&queue->lock);
    }

    cpumap_for_each(&oplist->cpumap, cpu) {
        request = &array->requests[cpu];

        mutex_lock(&request->lock);

        while (!request->done)
            condition_wait(&request->cond, &request->lock);

        mutex_unlock(&request->lock);
    }

    pmap_update_request_array_release(array);

out:
    cpumap_zero(&oplist->cpumap);
    oplist->pmap = NULL;
    oplist->nr_ops = 0;
}

static void
pmap_sync(void *arg)
{
    struct pmap_update_queue *queue;
    struct pmap_update_request *request;
    struct pmap_syncer *self;

    self = arg;
    queue = &self->queue;

    for (;;) {
        mutex_lock(&queue->lock);

        while (list_empty(&queue->requests))
            condition_wait(&queue->cond, &queue->lock);

        request = list_first_entry(&queue->requests,
                                   struct pmap_update_request, node);
        list_remove(&request->node);

        mutex_unlock(&queue->lock);

        pmap_update_local(request->oplist, request->nr_mappings);

        mutex_lock(&request->lock);
        request->done = 1;
        condition_signal(&request->cond);
        mutex_unlock(&request->lock);
    }
}

void
pmap_load(struct pmap *pmap)
{
    struct pmap_cpu_table *cpu_table;

    assert(!cpu_intr_enabled());
    assert(!thread_preempt_enabled());

    if (pmap_current() == pmap)
        return;

    /* TODO Lazy TLB invalidation */

    cpu_local_assign(pmap_current_ptr, pmap);

    /* TODO Implement per-CPU page tables for non-kernel pmaps */
    cpu_table = pmap->cpu_tables[cpu_id()];

#ifdef X86_PAE
    cpu_set_cr3(cpu_table->pdpt_pa);
#else /* X86_PAE */
    cpu_set_cr3(cpu_table->root_ptp_pa);
#endif /* X86_PAE */
}
