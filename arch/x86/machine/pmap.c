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

#define PMAP_PTEMAP_INDEX(va, shift) (((va) & PMAP_VA_MASK) >> (shift))

/*
 * Recursive mapping of PTEs.
 */
#define PMAP_PTEMAP_BASE ((pmap_pte_t *)VM_PMAP_PTEMAP_ADDRESS)

#define PMAP_LX_INDEX(shift) PMAP_PTEMAP_INDEX(VM_PMAP_PTEMAP_ADDRESS, shift)

/*
 * Base addresses of the page tables for each level in the recursive mapping.
 */
#define PMAP_L0_PTEMAP_BASE PMAP_PTEMAP_BASE
#define PMAP_L1_PTEMAP_BASE (PMAP_L0_PTEMAP_BASE + PMAP_LX_INDEX(PMAP_L0_SHIFT))
#define PMAP_L2_PTEMAP_BASE (PMAP_L1_PTEMAP_BASE + PMAP_LX_INDEX(PMAP_L1_SHIFT))
#define PMAP_L3_PTEMAP_BASE (PMAP_L2_PTEMAP_BASE + PMAP_LX_INDEX(PMAP_L2_SHIFT))

/*
 * Properties of a page translation level.
 */
struct pmap_pt_level {
    unsigned int bits;
    unsigned int shift;
    pmap_pte_t *ptemap_base;
    unsigned int ptes_per_ptp;
    pmap_pte_t mask;
};

/*
 * Table of page translation properties.
 */
static struct pmap_pt_level pmap_pt_levels[] __read_mostly = {
    { PMAP_L0_BITS, PMAP_L0_SHIFT, PMAP_L0_PTEMAP_BASE, PMAP_L0_PTES_PER_PTP,
      PMAP_L0_MASK },
    { PMAP_L1_BITS, PMAP_L1_SHIFT, PMAP_L1_PTEMAP_BASE, PMAP_L1_PTES_PER_PTP,
      PMAP_L1_MASK },
#if PMAP_NR_LEVELS == 4
    { PMAP_L2_BITS, PMAP_L2_SHIFT, PMAP_L2_PTEMAP_BASE, PMAP_L2_PTES_PER_PTP,
      PMAP_L2_MASK },
    { PMAP_L3_BITS, PMAP_L3_SHIFT, PMAP_L3_PTEMAP_BASE, PMAP_L3_PTES_PER_PTP,
      PMAP_L3_MASK }
#endif /* PMAP_NR_LEVELS == 4 */
};

/*
 * Number of mappings to reserve for the pmap module after the kernel.
 *
 * This pool of pure virtual memory can be used to reserve virtual addresses
 * before the VM system is initialized.
 *
 * List of users :
 *  - pmap_zero_mapping (1 page)
 *  - pmap_ptp_mapping (PMAP_NR_RPTPS pages)
 *  - CGA video memory (1 page)
 */
#define PMAP_RESERVED_PAGES (1 + PMAP_NR_RPTPS + 1)

/*
 * Addresses reserved for temporary mappings.
 */
struct pmap_tmp_mapping {
    struct mutex lock;
    unsigned long va;
} __aligned(CPU_L1_SIZE);

static struct pmap_tmp_mapping pmap_zero_mappings[MAX_CPUS];
static struct pmap_tmp_mapping pmap_ptp_mappings[MAX_CPUS];

/*
 * Reserved pages of virtual memory available for early allocation.
 */
static unsigned long pmap_boot_heap __initdata;
static unsigned long pmap_boot_heap_current __initdata;
static unsigned long pmap_boot_heap_end __initdata;

static char pmap_panic_inval_msg[] __bootdata
    = "pmap: invalid physical address";

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

static struct pmap kernel_pmap_store __read_mostly;
struct pmap *kernel_pmap __read_mostly = &kernel_pmap_store;
static struct pmap_cpu_table kernel_pmap_cpu_tables[MAX_CPUS] __read_mostly;

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
 * Maximum number of mappings for which individual TLB invalidations can be
 * performed. Global TLB flushes are done beyond this value.
 */
#define PMAP_UPDATE_MAX_MAPPINGS 64

/*
 * Structures related to inter-processor page table updates.
 */

/*
 * Per processor request, queued on a remote processor.
 *
 * A request refers to the operation list it's embedded within. The number of
 * mappings is used to determine whether it's best to flush individual TLB
 * entries or globally flush the TLB.
 */
struct pmap_update_request {
    struct list node;
    struct mutex lock;
    struct condition cond;
    unsigned int nr_mappings;
    int done;
} __aligned(CPU_L1_SIZE);

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
 * Operation lists are thread-local and apply to a single pmap. One list
 * includes operations that must be applied when updating a pmap. Updating
 * can be implicit, e.g. when a list has reached its maximum size, or
 * explicit, when pmap_update() is called.
 *
 * The cpumap is the union of all processors affected by at least one
 * operation.
 */
struct pmap_update_oplist {
    struct pmap_update_request requests[MAX_CPUS];

    struct cpumap cpumap;
    struct pmap *pmap;
    unsigned int nr_ops;
    struct pmap_update_op ops[PMAP_UPDATE_MAX_OPS];
};

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

static struct pmap_syncer pmap_syncers[MAX_CPUS];

static int pmap_do_remote_updates __read_mostly;

static struct kmem_cache pmap_cache;

static int pmap_ready __read_mostly;

static void __boot
pmap_boot_enter(pmap_pte_t *root_ptp, unsigned long va, phys_addr_t pa)
{
    const struct pmap_pt_level *pt_level, *pt_levels;
    unsigned long index;
    unsigned int level;
    pmap_pte_t *pt, *ptp, *pte;

    if (pa != (pa & PMAP_PA_MASK))
        boot_panic(pmap_panic_inval_msg);

    pt_levels = (void *)BOOT_VTOP((unsigned long)pmap_pt_levels);
    pt = root_ptp;

    for (level = PMAP_NR_LEVELS - 1; level != 0; level--) {
        pt_level = &pt_levels[level];
        index = (va >> pt_level->shift) & ((1UL << pt_level->bits) - 1);
        pte = &pt[index];

        if (*pte != 0)
            ptp = (void *)(unsigned long)(*pte & PMAP_PA_MASK);
        else {
            ptp = biosmem_bootalloc(1);
            *pte = ((unsigned long)ptp | PMAP_PTE_RW | PMAP_PTE_P)
                   & pt_level->mask;
        }

        pt = ptp;
    }

    /*
     * As a special case, a null physical address allocates the page tables
     * but doesn't create a mapping.
     */
    if (pa == 0)
        return;

    pte = &pt[(va >> PMAP_L0_SHIFT) & ((1UL << PMAP_L0_BITS) - 1)];
    *pte = (pa & PMAP_PA_MASK) | PMAP_PTE_RW | PMAP_PTE_P;
}

static void __boot
pmap_setup_ptemap(pmap_pte_t *root_ptp)
{
    const struct pmap_pt_level *pt_level, *pt_levels;
    phys_addr_t pa;
    unsigned long va, index;
    unsigned int i;

    pt_levels = (void *)BOOT_VTOP((unsigned long)pmap_pt_levels);
    pt_level = &pt_levels[PMAP_NR_LEVELS - 1];

    for (i = 0; i < PMAP_NR_RPTPS; i++) {
        va = VM_PMAP_PTEMAP_ADDRESS + (i * (1UL << pt_level->shift));
        index = (va >> pt_level->shift) & ((1UL << pt_level->bits) - 1);
        pa = (unsigned long)root_ptp + (i * PAGE_SIZE);
        root_ptp[index] = (pa | PMAP_PTE_RW | PMAP_PTE_P) & pt_level->mask;
    }
}

pmap_pte_t * __boot
pmap_setup_paging(void)
{
    struct pmap_cpu_table *cpu_table;
    pmap_pte_t *root_ptp;
    unsigned long va;
    phys_addr_t pa;
    size_t i, size;

    /*
     * Create the kernel mappings. The first two are for the .boot section and
     * the kernel code and data at high addresses respectively. The .boot
     * section mapping also acts as the mandatory identity mapping. The third
     * is the recursive mapping of PTEs.
     *
     * Any page table required for the virtual addresses that are reserved by
     * this module is also allocated.
     */

    root_ptp = biosmem_bootalloc(PMAP_NR_RPTPS);

    va = vm_page_trunc((unsigned long)&_boot);
    pa = va;
    size = vm_page_round((unsigned long)&_eboot) - va;

    for (i = 0; i < size; i += PAGE_SIZE) {
        pmap_boot_enter(root_ptp, va, pa);
        va += PAGE_SIZE;
        pa += PAGE_SIZE;
    }

    va = vm_page_trunc((unsigned long)&_init);
    pa = BOOT_VTOP(va);
    size = vm_page_round((unsigned long)&_end) - va;

    for (i = 0; i < size; i += PAGE_SIZE) {
        pmap_boot_enter(root_ptp, va, pa);
        va += PAGE_SIZE;
        pa += PAGE_SIZE;
    }

    for (i = 0; i < PMAP_RESERVED_PAGES; i++) {
        pmap_boot_enter(root_ptp, va, 0);
        va += PAGE_SIZE;
    }

    assert(va > (unsigned long)&_end);

    pmap_setup_ptemap(root_ptp);

    cpu_table = (void *)BOOT_VTOP((unsigned long)&kernel_pmap_cpu_tables[0]);
    cpu_table->root_ptp_pa = (unsigned long)root_ptp;

#ifdef X86_PAE
    cpu_table->pdpt = pmap_cpu_kpdpts[0];
    cpu_table->pdpt_pa = BOOT_VTOP((unsigned long)pmap_cpu_kpdpts[0]);
    root_ptp = (void *)cpu_table->pdpt_pa;

    for (i = 0; i < PMAP_NR_RPTPS; i++)
        root_ptp[i] = (cpu_table->root_ptp_pa + (i * PAGE_SIZE)) | PMAP_PTE_P;

    cpu_enable_pae();
#endif /* X86_PAE */

    return root_ptp;
}

pmap_pte_t * __boot
pmap_ap_setup_paging(void)
{
    struct pmap_cpu_table *cpu_table;
    struct pmap *pmap;
    pmap_pte_t *root_ptp;

    pmap = (void *)BOOT_VTOP((unsigned long)&kernel_pmap_store);
    cpu_table = (void *)BOOT_VTOP((unsigned long)pmap->cpu_tables[boot_ap_id]);

#ifdef X86_PAE
    root_ptp = (void *)cpu_table->pdpt_pa;
    cpu_enable_pae();
#else /* X86_PAE */
    root_ptp = (void *)cpu_table->root_ptp_pa;
#endif /* X86_PAE */

    return root_ptp;
}

/*
 * Helper function for initialization procedures that require post-fixing
 * page properties.
 */
static void __init
pmap_walk_vas(unsigned long start, unsigned long end, int skip_null,
              void (*f)(pmap_pte_t *pte))
{
    const struct pmap_pt_level *pt_level;
    unsigned long va, index;
    unsigned int level;
    pmap_pte_t *pte;

    if (start == 0)
        start = PAGE_SIZE;

    assert(vm_page_aligned(start));
    assert(start < end);
#ifdef __LP64__
    assert((start <= VM_MAX_ADDRESS) || (start >= VM_PMAP_PTEMAP_ADDRESS));
#endif /* __LP64__ */

    va = start;

    do {
#ifdef __LP64__
        /* Handle long mode canonical form */
        if (va == ((PMAP_VA_MASK >> 1) + 1))
            va = ~(PMAP_VA_MASK >> 1);
#endif /* __LP64__ */

        for (level = PMAP_NR_LEVELS - 1; level < PMAP_NR_LEVELS; level--) {
            pt_level = &pmap_pt_levels[level];
            index = PMAP_PTEMAP_INDEX(va, pt_level->shift);
            pte = &pt_level->ptemap_base[index];

            if ((*pte == 0) && (skip_null || (level != 0))) {
                pte = NULL;
                va = P2END(va, 1UL << pt_level->shift);
                break;
            }
        }

        if (pte == NULL)
            continue;

        f(pte);
        va += PAGE_SIZE;
    } while ((va < end) && (va >= start));
}

static void __init
pmap_setup_global_page(pmap_pte_t *pte)
{
    *pte |= PMAP_PTE_G;
}

static void __init
pmap_setup_global_pages(void)
{
    pmap_walk_vas(VM_MAX_KERNEL_ADDRESS, (unsigned long)-1, 1,
                  pmap_setup_global_page);
    pmap_pt_levels[0].mask |= PMAP_PTE_G;
    cpu_enable_global_pages();
}

static void
pmap_update_oplist_ctor(void *arg)
{
    struct pmap_update_oplist *oplist;
    unsigned int i;

    oplist = arg;

    for (i = 0; i < ARRAY_SIZE(oplist->requests); i++) {
        mutex_init(&oplist->requests[i].lock);
        condition_init(&oplist->requests[i].cond);
        oplist->requests[i].nr_mappings = 0;
        oplist->requests[i].done = 0;
    }

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
    }
}

static void
pmap_update_oplist_inc_nr_ops(struct pmap_update_oplist *oplist,
                              struct pmap_update_op *op)
{
    cpumap_or(&oplist->cpumap, &op->cpumap);
    oplist->nr_ops++;
}

static void
pmap_update_oplist_inc_nr_mappings(struct pmap_update_oplist *oplist,
                                   struct pmap_update_op *op)
{
    struct pmap_update_request *request;
    int cpu;

    cpumap_for_each(&op->cpumap, cpu) {
        request = &oplist->requests[cpu];
        request->nr_mappings++;
    }
}

static void __init
pmap_syncer_init(struct pmap_syncer *syncer)
{
    char name[EVCNT_NAME_SIZE];
    struct pmap_update_queue *queue;
    unsigned int cpu;

    cpu = syncer - pmap_syncers;
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
    unsigned long va;
    unsigned int cpu;

    for (cpu = 0; cpu < ARRAY_SIZE(kernel_pmap->cpu_tables); cpu++) {
        cpu_table = &kernel_pmap_cpu_tables[cpu];
        kernel_pmap->cpu_tables[cpu] = cpu_table;
        mutex_init(&cpu_table->lock);
    }

    cpu_percpu_set_pmap(kernel_pmap);

    pmap_boot_heap = (unsigned long)&_end;
    pmap_boot_heap_current = pmap_boot_heap;
    pmap_boot_heap_end = pmap_boot_heap + (PMAP_RESERVED_PAGES * PAGE_SIZE);

    pmap_prot_table[VM_PROT_NONE] = 0;
    pmap_prot_table[VM_PROT_READ] = 0;
    pmap_prot_table[VM_PROT_WRITE] = PMAP_PTE_RW;
    pmap_prot_table[VM_PROT_WRITE | VM_PROT_READ] = PMAP_PTE_RW;
    pmap_prot_table[VM_PROT_EXECUTE] = 0;
    pmap_prot_table[VM_PROT_EXECUTE | VM_PROT_READ] = 0;
    pmap_prot_table[VM_PROT_EXECUTE | VM_PROT_WRITE] = PMAP_PTE_RW;
    pmap_prot_table[VM_PROT_ALL] = PMAP_PTE_RW;

    va = pmap_bootalloc(1);

    for (cpu = 0; cpu < MAX_CPUS; cpu++) {
        mutex_init(&pmap_zero_mappings[cpu].lock);
        pmap_zero_mappings[cpu].va = va;
    }

    va = pmap_bootalloc(PMAP_NR_RPTPS);

    for (cpu = 0; cpu < MAX_CPUS; cpu++) {
        mutex_init(&pmap_ptp_mappings[cpu].lock);
        pmap_ptp_mappings[cpu].va = va;
    }

    pmap_syncer_init(&pmap_syncers[0]);

    pmap_update_oplist_ctor(&pmap_booter_oplist);
    thread_key_create(&pmap_oplist_tsd_key, pmap_update_oplist_destroy);
    thread_set_specific(pmap_oplist_tsd_key, &pmap_booter_oplist);

    cpumap_zero(&pmap_booter_cpumap);
    cpumap_set(&pmap_booter_cpumap, 0);

    for (va = (unsigned long)&_text;
         va < (unsigned long)&_rodata;
         va += PAGE_SIZE)
        pmap_protect(kernel_pmap, va, VM_PROT_READ | VM_PROT_EXECUTE,
                     &pmap_booter_cpumap);

    for (va = (unsigned long)&_rodata;
         va < (unsigned long)&_data;
         va += PAGE_SIZE)
        pmap_protect(kernel_pmap, va, VM_PROT_READ, &pmap_booter_cpumap);

    if (cpu_has_global_pages())
        pmap_setup_global_pages();

    pmap_update(kernel_pmap);
}

void __init
pmap_ap_bootstrap(void)
{
    cpu_percpu_set_pmap(kernel_pmap);

    if (cpu_has_global_pages())
        cpu_enable_global_pages();
    else
        cpu_tlb_flush();
}

unsigned long __init
pmap_bootalloc(unsigned int nr_pages)
{
    unsigned long page;
    size_t size;

    assert(nr_pages > 0);

    page = pmap_boot_heap_current;
    size = nr_pages * PAGE_SIZE;
    pmap_boot_heap_current += size;

    assert(pmap_boot_heap_current > pmap_boot_heap);
    assert(pmap_boot_heap_current <= pmap_boot_heap_end);

    return page;
}

/*
 * Check address range with regard to physical map.
 *
 * Note that there is no addressing restriction on the kernel pmap.
 */
#define pmap_assert_range(pmap, start, end)     \
    assert(((start) < (end))                    \
           && (((pmap) == kernel_pmap)          \
               || ((end) <= VM_MAX_ADDRESS)))   \

static inline void
pmap_pte_set(pmap_pte_t *pte, phys_addr_t pa, pmap_pte_t pte_bits,
             unsigned int level)
{
    assert(level < PMAP_NR_LEVELS);
    *pte = ((pa & PMAP_PA_MASK) | PMAP_PTE_P | pte_bits)
           & pmap_pt_levels[level].mask;
}

static inline void
pmap_pte_clear(pmap_pte_t *pte)
{
    *pte = 0;
}

/*
 * The pmap_kenter() and pmap_kremove() functions are quicker and simpler
 * versions of pmap_enter() and pmap_remove() that only operate on the
 * kernel physical map and assume the page tables for the target mappings
 * have already been prepared.
 */

static void
pmap_kenter(unsigned long va, phys_addr_t pa, int prot)
{
    pmap_pte_t *pte;

    pmap_assert_range(kernel_pmap, va, va + PAGE_SIZE);

    pte = PMAP_PTEMAP_BASE + PMAP_PTEMAP_INDEX(va, PMAP_L0_SHIFT);
    pmap_pte_set(pte, pa, PMAP_PTE_G | pmap_prot_table[prot & VM_PROT_ALL], 0);
}

static void
pmap_kremove(unsigned long start, unsigned long end)
{
    pmap_pte_t *pte;

    pmap_assert_range(kernel_pmap, start, end);

    while (start < end) {
        pte = PMAP_PTEMAP_BASE + PMAP_PTEMAP_INDEX(start, PMAP_L0_SHIFT);
        pmap_pte_clear(pte);
        start += PAGE_SIZE;
    }
}

static void
pmap_zero_page(phys_addr_t pa)
{
    struct pmap_tmp_mapping *zero_mapping;
    unsigned long va;

    thread_pin();
    zero_mapping = &pmap_zero_mappings[cpu_id()];
    mutex_lock(&zero_mapping->lock);
    va = zero_mapping->va;
    pmap_kenter(va, pa, VM_PROT_WRITE);
    cpu_tlb_flush_va(va);
    memset((void *)va, 0, PAGE_SIZE);
    pmap_kremove(va, va + PAGE_SIZE);
    cpu_tlb_flush_va(va);
    mutex_unlock(&zero_mapping->lock);
    thread_unpin();
}

static struct pmap_tmp_mapping *
pmap_map_ptp(phys_addr_t pa, unsigned int nr_pages)
{
    struct pmap_tmp_mapping *ptp_mapping;
    unsigned long va;
    unsigned int i, offset;

#if PMAP_NR_RPTPS != 1
    assert((nr_pages == 1) || (nr_pages == PMAP_NR_RPTPS));
#else
    assert(nr_pages == 1);
#endif

    thread_pin();
    ptp_mapping  = &pmap_ptp_mappings[cpu_id()];
    mutex_lock(&ptp_mapping->lock);

    for (i = 0; i < nr_pages; i++) {
        offset = i * PAGE_SIZE;
        va = ptp_mapping->va + offset;
        pmap_kenter(va, pa + offset, VM_PROT_READ | VM_PROT_WRITE);
        cpu_tlb_flush_va(va);
    }

    return ptp_mapping;
}

static void
pmap_unmap_ptp(struct pmap_tmp_mapping *ptp_mapping, unsigned int nr_pages)
{
    unsigned long va;
    unsigned int i;

    assert(thread_pinned());

#if PMAP_NR_RPTPS != 1
    assert((nr_pages == 1) || (nr_pages == PMAP_NR_RPTPS));
#else
    assert(nr_pages == 1);
#endif

    mutex_assert_locked(&ptp_mapping->lock);

    va = ptp_mapping->va;
    pmap_kremove(va, va + (PMAP_NR_RPTPS * PAGE_SIZE));

    for (i = 0; i < nr_pages; i++)
        cpu_tlb_flush_va(va + (i * PAGE_SIZE));

    mutex_unlock(&ptp_mapping->lock);
    thread_unpin();
}

static void __init
pmap_setup_inc_nr_ptes(pmap_pte_t *pte)
{
    struct vm_page *page;

    page = vm_kmem_lookup_page(vm_page_trunc((unsigned long)pte));
    assert(page != NULL);
    page->pmap_page.nr_ptes++;
}

static void __init
pmap_setup_set_ptp_type(pmap_pte_t *pte)
{
    struct vm_page *page;

    page = vm_kmem_lookup_page(vm_page_trunc((unsigned long)pte));
    assert(page != NULL);

    if (vm_page_type(page) != VM_PAGE_PMAP) {
        assert(vm_page_type(page) == VM_PAGE_RESERVED);
        vm_page_set_type(page, 0, VM_PAGE_PMAP);
    }
}

static void __init
pmap_setup_count_ptes(void)
{
    pmap_walk_vas(0, pmap_boot_heap, 1, pmap_setup_inc_nr_ptes);
    pmap_walk_vas(0, pmap_boot_heap, 1, pmap_setup_set_ptp_type);

    /* Account for the reserved mappings, whether they exist or not */
    pmap_walk_vas(pmap_boot_heap, pmap_boot_heap_end, 0,
                  pmap_setup_inc_nr_ptes);
    pmap_walk_vas(pmap_boot_heap, pmap_boot_heap_end, 0,
                  pmap_setup_set_ptp_type);
}

void __init
pmap_setup(void)
{
    pmap_setup_count_ptes();

    kmem_cache_init(&pmap_cache, "pmap", sizeof(struct pmap),
                    0, NULL, NULL, NULL, 0);
    kmem_cache_init(&pmap_update_oplist_cache, "pmap_update_oplist",
                    sizeof(struct pmap_update_oplist), CPU_L1_SIZE,
                    pmap_update_oplist_ctor, NULL, NULL, 0);

    pmap_ready = 1;
}

static void __init
pmap_copy_cpu_table_recursive(struct vm_page *page, phys_addr_t pa,
                              unsigned long start_va, unsigned int level)
{
    const struct pmap_pt_level *pt_level;
    struct pmap_tmp_mapping *mapping;
    const struct vm_page *orig_page;
    pmap_pte_t *spt, *dpt;
    phys_addr_t lower_pa;
    unsigned int i, nr_ptps, first = first, last = last;
    unsigned long va;
    int is_root;

    pt_level = &pmap_pt_levels[level];
    spt = &pt_level->ptemap_base[PMAP_PTEMAP_INDEX(start_va, pt_level->shift)];

    orig_page = vm_kmem_lookup_page((unsigned long)spt);
    assert(orig_page != NULL);
    page->pmap_page.nr_ptes = orig_page->pmap_page.nr_ptes;

    if (level == PMAP_NR_LEVELS - 1) {
        is_root = 1;
        nr_ptps = PMAP_NR_RPTPS;
        first = PMAP_PTEMAP_INDEX(VM_PMAP_PTEMAP_ADDRESS, pt_level->shift);
        last = first + (PMAP_NR_RPTPS - 1);
    } else {
        is_root = 0;
        nr_ptps = 1;
    }

    mapping = pmap_map_ptp(pa, nr_ptps);
    dpt = (pmap_pte_t *)mapping->va;

    if (level == 0)
        memcpy(dpt, spt, pt_level->ptes_per_ptp * sizeof(pmap_pte_t));
    else {
        memset(dpt, 0, pt_level->ptes_per_ptp * sizeof(pmap_pte_t));

        for (i = 0, va = start_va;
             i < pt_level->ptes_per_ptp;
             i++, va = P2END(va, 1UL << pt_level->shift)) {
#ifdef __LP64__
            /* Handle long mode canonical form */
            if (va == ((PMAP_VA_MASK >> 1) + 1))
                va = ~(PMAP_VA_MASK >> 1);
#endif /* __LP64__ */

            if (spt[i] == 0)
                continue;

            /* Install the recursive mapping */
            if (is_root && (i >= first) && (i <= last)) {
                dpt[i] = (spt[i] & ~PMAP_PA_MASK)
                         | ((pa + ((i - first) * PAGE_SIZE)) & PMAP_PA_MASK);
                continue;
            }

            page = vm_page_alloc(0, VM_PAGE_PMAP);
            assert(page != NULL);
            lower_pa = vm_page_to_pa(page);
            dpt[i] = (spt[i] & ~PMAP_PA_MASK) | (lower_pa & PMAP_PA_MASK);

            pmap_unmap_ptp(mapping, nr_ptps);

            pmap_copy_cpu_table_recursive(page, lower_pa, va, level - 1);

            mapping = pmap_map_ptp(pa, nr_ptps);
            dpt = (pmap_pte_t *)mapping->va;
        }
    }

    pmap_unmap_ptp(mapping, nr_ptps);
}

static void __init
pmap_copy_cpu_table(unsigned int cpu)
{
    struct pmap_cpu_table *cpu_table;
    struct vm_page *page;
    phys_addr_t pa;

    cpu_table = kernel_pmap->cpu_tables[cpu];
    page = vm_page_alloc(PMAP_RPTP_ORDER, VM_PAGE_PMAP);
    assert(page != NULL);
    pa = vm_page_to_pa(page);
    pmap_copy_cpu_table_recursive(page, pa, 0, PMAP_NR_LEVELS - 1);
    cpu_table->root_ptp_pa = pa;

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
    struct thread_attr attr;
    struct pmap_syncer *syncer;
    struct cpumap *cpumap;
    unsigned int cpu;
    int error;

    for (cpu = 1; cpu < cpu_count(); cpu++)
        pmap_syncer_init(&pmap_syncers[cpu]);

    error = cpumap_create(&cpumap);

    if (error)
        panic("pmap: unable to create syncer cpumap");

    for (cpu = 0; cpu < cpu_count(); cpu++) {
        syncer = &pmap_syncers[cpu];
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
pmap_enter_ptemap_inc_nr_ptes(const pmap_pte_t *pte)
{
    struct vm_page *page;

    if (!pmap_ready)
        return;

    page = vm_kmem_lookup_page(vm_page_trunc((unsigned long)pte));
    assert(page != NULL);
    assert(vm_page_type(page) == VM_PAGE_PMAP);
    page->pmap_page.nr_ptes++;
}

static void
pmap_enter_ptemap(struct pmap *pmap, unsigned long va, phys_addr_t pa, int prot)
{
    const struct pmap_pt_level *pt_level;
    struct vm_page *page;
    unsigned long index;
    unsigned int level;
    pmap_pte_t *pte, pte_bits;
    phys_addr_t ptp_pa;

    pte_bits = PMAP_PTE_RW;

    /*
     * The recursive mapping is protected from user access by not setting
     * the U/S bit when inserting the root page table into itself.
     */
    if (pmap != kernel_pmap)
        pte_bits |= PMAP_PTE_US;

    for (level = PMAP_NR_LEVELS - 1; level != 0; level--) {
        pt_level = &pmap_pt_levels[level];
        index = PMAP_PTEMAP_INDEX(va, pt_level->shift);
        pte = &pt_level->ptemap_base[index];

        if (*pte != 0)
            continue;

        if (!vm_page_ready()) {
            assert(pmap == kernel_pmap);
            ptp_pa = vm_page_bootalloc();
        } else {
            page = vm_page_alloc(0, VM_PAGE_PMAP);
            assert(page != NULL);
            ptp_pa = vm_page_to_pa(page);
        }

        pmap_enter_ptemap_inc_nr_ptes(pte);
        pmap_zero_page(ptp_pa);
        pmap_pte_set(pte, ptp_pa, pte_bits, level);
    }

    pte = PMAP_PTEMAP_BASE + PMAP_PTEMAP_INDEX(va, PMAP_L0_SHIFT);
    pmap_enter_ptemap_inc_nr_ptes(pte);
    pte_bits = ((pmap == kernel_pmap) ? PMAP_PTE_G : PMAP_PTE_US)
               | pmap_prot_table[prot & VM_PROT_ALL];
    pmap_pte_set(pte, pa, pte_bits, 0);
}

static void
pmap_enter_local(struct pmap *pmap, unsigned long va, phys_addr_t pa,
                 int prot, int flags)
{
    (void)flags;

    if ((pmap == kernel_pmap) || (pmap == pmap_current())) {
        pmap_enter_ptemap(pmap, va, pa, prot);
        return;
    }

    /* TODO Handle unloaded pmaps */
    panic("pmap: unable to handle unloaded pmap, not implemented yet");
}

void
pmap_enter(struct pmap *pmap, unsigned long va, phys_addr_t pa,
           int prot, int flags)
{
    struct pmap_update_oplist *oplist;
    struct pmap_update_op *op;

    pmap_assert_range(pmap, va, va + PAGE_SIZE);

    oplist = pmap_update_oplist_get();
    pmap_update_oplist_prepare(oplist, pmap);

    op = &oplist->ops[oplist->nr_ops];

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

    pmap_update_oplist_inc_nr_ops(oplist, op);
    pmap_update_oplist_inc_nr_mappings(oplist, op);
}

static void
pmap_remove_ptemap_dec_nr_ptes(pmap_pte_t *pte, unsigned long va, unsigned int level)
{
    const struct pmap_pt_level *pt_level;
    struct vm_page *page;
    unsigned long index;

    if (!pmap_ready)
        return;

    page = vm_kmem_lookup_page(vm_page_trunc((unsigned long)pte));
    assert(page != NULL);
    assert(vm_page_type(page) == VM_PAGE_PMAP);
    assert(page->pmap_page.nr_ptes != 0);
    page->pmap_page.nr_ptes--;

    if (page->pmap_page.nr_ptes != 0)
        return;

    level++;

    if (level == PMAP_NR_LEVELS)
        return;

    pt_level = &pmap_pt_levels[level];
    index = PMAP_PTEMAP_INDEX(va, pt_level->shift);
    pte = &pt_level->ptemap_base[index];
    pmap_pte_clear(pte);
    pmap_remove_ptemap_dec_nr_ptes(pte, va, level);
    vm_page_free(page, 0);
}

static void
pmap_remove_ptemap(struct pmap *pmap, unsigned long start, unsigned long end)
{
    pmap_pte_t *pte;

    (void)pmap;

    while (start < end) {
        pte = PMAP_PTEMAP_BASE + PMAP_PTEMAP_INDEX(start, PMAP_L0_SHIFT);
        pmap_pte_clear(pte);
        pmap_remove_ptemap_dec_nr_ptes(pte, start, 0);
        start += PAGE_SIZE;
    }
}

static void
pmap_remove_local(struct pmap *pmap, unsigned long start, unsigned long end)
{
    if ((pmap == kernel_pmap) || (pmap == pmap_current())) {
        pmap_remove_ptemap(pmap, start, end);
        return;
    }

    /* TODO Handle unloaded pmaps */
    panic("pmap: unable to handle unloaded pmap, not implemented yet");
}

void
pmap_remove(struct pmap *pmap, unsigned long va, const struct cpumap *cpumap)
{
    struct pmap_update_oplist *oplist;
    struct pmap_update_op *op;

    pmap_assert_range(pmap, va, va + PAGE_SIZE);

    oplist = pmap_update_oplist_get();
    pmap_update_oplist_prepare(oplist, pmap);

    /* Attempt naive merge with previous operation */
    if (oplist->nr_ops != 0) {
        op = &oplist->ops[oplist->nr_ops - 1];

        if ((op->operation == PMAP_UPDATE_OP_REMOVE)
            && (op->remove_args.end == va)
            && (cpumap_cmp(&op->cpumap, cpumap) == 0)) {
            op->remove_args.end = va + PAGE_SIZE;
            goto out;
        }
    }

    op = &oplist->ops[oplist->nr_ops];
    cpumap_copy(&op->cpumap, cpumap);
    op->operation = PMAP_UPDATE_OP_REMOVE;
    op->remove_args.start = va;
    op->remove_args.end = va + PAGE_SIZE;

    pmap_update_oplist_inc_nr_ops(oplist, op);

out:
    pmap_update_oplist_inc_nr_mappings(oplist, op);
}

static void
pmap_protect_ptemap(unsigned long start, unsigned long end, int prot)
{
    pmap_pte_t *pte, flags;

    flags = pmap_prot_table[prot & VM_PROT_ALL];

    while (start < end) {
        pte = PMAP_PTEMAP_BASE + PMAP_PTEMAP_INDEX(start, PMAP_L0_SHIFT);
        *pte = (*pte & ~PMAP_PTE_PROT_MASK) | flags;
        start += PAGE_SIZE;
    }
}

static void
pmap_protect_local(struct pmap *pmap, unsigned long start, unsigned long end,
                   int prot)
{
    if ((pmap == kernel_pmap) || (pmap == pmap_current())) {
        pmap_protect_ptemap(start, end, prot);
        return;
    }

    /* TODO Handle unloaded pmaps */
    panic("pmap: unable to handle unloaded pmap, not implemented yet");
}

void
pmap_protect(struct pmap *pmap, unsigned long va, int prot,
             const struct cpumap *cpumap)
{
    struct pmap_update_oplist *oplist;
    struct pmap_update_op *op;

    pmap_assert_range(pmap, va, va + PAGE_SIZE);

    oplist = pmap_update_oplist_get();
    pmap_update_oplist_prepare(oplist, pmap);

    /* Attempt naive merge with previous operation */
    if (oplist->nr_ops != 0) {
        op = &oplist->ops[oplist->nr_ops - 1];

        if ((op->operation == PMAP_UPDATE_OP_PROTECT)
            && (op->protect_args.end == va)
            && (op->protect_args.prot == prot)
            && (cpumap_cmp(&op->cpumap, cpumap) == 0)) {
            op->protect_args.end = va + PAGE_SIZE;
            goto out;
        }
    }

    op = &oplist->ops[oplist->nr_ops];
    cpumap_copy(&op->cpumap, cpumap);
    op->operation = PMAP_UPDATE_OP_PROTECT;
    op->protect_args.start = va;
    op->protect_args.end = va + PAGE_SIZE;
    op->protect_args.prot = prot;

    pmap_update_oplist_inc_nr_ops(oplist, op);

out:
    pmap_update_oplist_inc_nr_mappings(oplist, op);
}

static phys_addr_t
pmap_extract_ptemap(unsigned long va)
{
    const struct pmap_pt_level *pt_level;
    unsigned long index;
    unsigned int level;
    pmap_pte_t *pte;

    for (level = PMAP_NR_LEVELS - 1; level < PMAP_NR_LEVELS; level--) {
        pt_level = &pmap_pt_levels[level];
        index = PMAP_PTEMAP_INDEX(va, pt_level->shift);
        pte = &pt_level->ptemap_base[index];

        if (*pte == 0)
            return 0;
    }

    return *pte & PMAP_PA_MASK;
}

phys_addr_t
pmap_extract(struct pmap *pmap, unsigned long va)
{
    pmap_assert_range(pmap, va, va + PAGE_SIZE);

    if ((pmap == kernel_pmap) || (pmap == pmap_current()))
        return pmap_extract_ptemap(va);

    /* TODO Handle unloaded pmaps */
    panic("pmap: unable to handle unloaded pmap, not implemented yet");
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
pmap_update_enter(struct pmap *pmap, int flush_tlb_entries,
                  const struct pmap_update_enter_args *args)
{
    pmap_enter_local(pmap, args->va, args->pa, args->prot, args->flags);

    if (flush_tlb_entries)
        pmap_flush_tlb(pmap, args->va, args->va + PAGE_SIZE);
}

static void
pmap_update_remove(struct pmap *pmap, int flush_tlb_entries,
                   const struct pmap_update_remove_args *args)
{
    pmap_remove_local(pmap, args->start, args->end);

    if (flush_tlb_entries)
        pmap_flush_tlb(pmap, args->start, args->end);
}

static void
pmap_update_protect(struct pmap *pmap, int flush_tlb_entries,
                    const struct pmap_update_protect_args *args)
{
    pmap_protect_local(pmap, args->start, args->end, args->prot);

    if (flush_tlb_entries)
        pmap_flush_tlb(pmap, args->start, args->end);
}

static void
pmap_update_local(const struct pmap_update_oplist *oplist,
                  unsigned int nr_mappings)
{
    const struct pmap_update_op *op;
    struct pmap_syncer *syncer;
    unsigned int i, cpu;
    int flush_tlb_entries;

    cpu = cpu_id();
    syncer = &pmap_syncers[cpu];
    evcnt_inc(&syncer->ev_update);
    flush_tlb_entries = (nr_mappings <= PMAP_UPDATE_MAX_MAPPINGS);

    for (i = 0; i < oplist->nr_ops; i++) {
        op = &oplist->ops[i];

        if (!cpumap_test(&op->cpumap, cpu))
            continue;

        switch (op->operation) {
        case PMAP_UPDATE_OP_ENTER:
            evcnt_inc(&syncer->ev_update_enter);
            pmap_update_enter(oplist->pmap, flush_tlb_entries,
                              &op->enter_args);
            break;
        case PMAP_UPDATE_OP_REMOVE:
            evcnt_inc(&syncer->ev_update_remove);
            pmap_update_remove(oplist->pmap, flush_tlb_entries,
                               &op->remove_args);
            break;
        case PMAP_UPDATE_OP_PROTECT:
            evcnt_inc(&syncer->ev_update_protect);
            pmap_update_protect(oplist->pmap, flush_tlb_entries,
                                &op->protect_args);
            break;
        default:
            assert(!"invalid update operation");
        }
    }

    if (!flush_tlb_entries)
        pmap_flush_tlb_all(oplist->pmap);
}

void
pmap_update(struct pmap *pmap)
{
    struct pmap_update_oplist *oplist;
    struct pmap_update_request *request;
    struct pmap_update_queue *queue;
    int cpu;

    oplist = pmap_update_oplist_get();

    if (pmap != oplist->pmap)
        return;

    assert(oplist->nr_ops != 0);

    if (!pmap_do_remote_updates) {
        request = &oplist->requests[cpu_id()];
        pmap_update_local(oplist, request->nr_mappings);

        cpumap_for_each(&oplist->cpumap, cpu) {
            request = &oplist->requests[cpu];
            request->nr_mappings = 0;
        }

        goto out;
    }

    cpumap_for_each(&oplist->cpumap, cpu) {
        request = &oplist->requests[cpu];
        queue = &pmap_syncers[cpu].queue;

        assert(!request->done);
        assert(request->nr_mappings != 0);

        mutex_lock(&queue->lock);
        list_insert_tail(&queue->requests, &request->node);
        condition_signal(&queue->cond);
        mutex_unlock(&queue->lock);
    }

    cpumap_for_each(&oplist->cpumap, cpu) {
        request = &oplist->requests[cpu];

        mutex_lock(&request->lock);

        while (!request->done)
            condition_wait(&request->cond, &request->lock);

        request->nr_mappings = 0;
        request->done = 0;

        mutex_unlock(&request->lock);
    }

out:
    cpumap_zero(&oplist->cpumap);
    oplist->pmap = NULL;
    oplist->nr_ops = 0;
}

static void
pmap_sync(void *arg)
{
    const struct pmap_update_oplist *oplist;
    struct pmap_update_queue *queue;
    struct pmap_update_request *request, *requests;
    struct pmap_syncer *self;
    unsigned int cpu;

    self = arg;
    queue = &self->queue;
    cpu = self - pmap_syncers;

    for (;;) {
        mutex_lock(&queue->lock);

        while (list_empty(&queue->requests))
            condition_wait(&queue->cond, &queue->lock);

        request = list_first_entry(&queue->requests,
                                   struct pmap_update_request, node);
        list_remove(&request->node);

        mutex_unlock(&queue->lock);

        requests = request - cpu;
        oplist = structof(requests, struct pmap_update_oplist, requests);
        pmap_update_local(oplist, request->nr_mappings);

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

    cpu_percpu_set_pmap(pmap);

    /* TODO Implement per-CPU page tables for non-kernel pmaps */
    cpu_table = pmap->cpu_tables[cpu_id()];

#ifdef X86_PAE
    cpu_set_cr3(cpu_table->pdpt_pa);
#else /* X86_PAE */
    cpu_set_cr3(cpu_table->root_ptp_pa);
#endif /* X86_PAE */
}
