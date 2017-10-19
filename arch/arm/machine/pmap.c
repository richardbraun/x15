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

#include <assert.h>
#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <kern/bootmem.h>
#include <kern/cpumap.h>
#include <kern/error.h>
#include <kern/init.h>
#include <kern/kmem.h>
#include <kern/list.h>
#include <kern/log.h>
#include <kern/macros.h>
#include <kern/mutex.h>
#include <kern/panic.h>
#include <kern/percpu.h>
#include <kern/spinlock.h>
#include <kern/syscnt.h>
#include <kern/thread.h>
#include <machine/boot.h>
#include <machine/cpu.h>
#include <machine/page.h>
#include <machine/pmap.h>
#include <machine/tcb.h>
#include <machine/trap.h>
#include <machine/types.h>
#include <vm/vm_kmem.h>
#include <vm/vm_page.h>
#include <vm/vm_ptable.h>
#include <vm/vm_prot.h>

#define PMAP_PTE_B              0x00000004
#define PMAP_PTE_C              0x00000008

#define PMAP_PTE_L0_RW          0x00000030
#define PMAP_PTE_L1_RW          0x00000c00

/*
 * Page table level properties.
 */

#define PMAP_NR_LEVELS          2
#define PMAP_L0_BITS            8
#define PMAP_L1_BITS            12

#define PMAP_VA_MASK            0xffffffff

#define PMAP_PA_L0_MASK         0xfffff000
#define PMAP_PA_L1_MASK         0xfffffc00

#define PMAP_L0_SKIP            12
#define PMAP_L1_SKIP            (PMAP_L0_SKIP + PMAP_L0_BITS)

#define PMAP_L0_PTES_PER_PT     (1 << PMAP_L0_BITS)
#define PMAP_L1_PTES_PER_PT     (1 << PMAP_L1_BITS)

static pmap_pte_t __boot
pmap_make_coarse_pte(phys_addr_t pa, int prot)
{
    (void)prot;

    assert((pa & PMAP_PA_L1_MASK) == pa);
    return pa | PMAP_PTE_TYPE_COARSE;
}

static pmap_pte_t __boot
pmap_make_small_page_pte(phys_addr_t pa, int prot)
{
    (void)prot;

    assert((pa & PMAP_PA_L0_MASK) == pa);
    return pa | PMAP_PTE_L0_RW | PMAP_PTE_C | PMAP_PTE_B | PMAP_PTE_TYPE_SMALL;
}

static pmap_pte_t __boot
pmap_make_section_pte(phys_addr_t pa, int prot)
{
    (void)prot;

    assert((pa & 0xfff00000) == pa);
    return pa | PMAP_PTE_L1_RW | PMAP_PTE_C | PMAP_PTE_B | PMAP_PTE_TYPE_SECTION;
}

/*
 * Table of properties per page table level.
 */
static const struct vm_ptable_level pmap_pt_levels[] = {
    {
        PMAP_L0_SKIP,
        PMAP_L0_BITS,
        PMAP_L0_PTES_PER_PT,
        NULL,
        pmap_make_small_page_pte,
    },
    {
        PMAP_L1_SKIP,
        PMAP_L1_BITS,
        PMAP_L1_PTES_PER_PT,
        pmap_make_coarse_pte,
        pmap_make_section_pte,
    },
};

struct pmap {
    struct vm_ptable ptable;
};

struct pmap pmap_kernel_pmap;

/*
 * Flags related to page protection.
 */
#define PMAP_PTE_PROT_MASK PMAP_PTE_RW

/*
 * Table used to convert machine independent protection flags to architecture
 * specific PTE bits.
 */
static pmap_pte_t pmap_prot_table[VM_PROT_ALL + 1] __read_mostly;

static struct kmem_cache pmap_cache;

static char pmap_panic_directmap_msg[] __bootdata
    = "vm_ptable: invalid direct physical mapping";

static unsigned long __boot
pmap_boot_get_large_pgsize(void)
{
#if 0
    return (1 << PMAP_L1_SKIP);
#else
    return PAGE_SIZE;
#endif
}

pmap_pte_t * __boot
pmap_setup_paging(void)
{
    const struct vm_ptable_level *pt_levels;
    unsigned long i, size, pgsize;
    phys_addr_t pa, directmap_end;
    struct vm_ptable *ptable;
    struct pmap *kernel_pmap;
    uintptr_t va;

    pt_levels = (void *)BOOT_VTOP((uintptr_t)&pmap_pt_levels);
    kernel_pmap = (void *)BOOT_VTOP((uintptr_t)&pmap_kernel_pmap);
    ptable = &kernel_pmap->ptable;

    /* Use large pages for the direct physical mapping when possible */
    pgsize = pmap_boot_get_large_pgsize();

    /* TODO LPAE */

    vm_ptable_init(ptable, pt_levels, ARRAY_SIZE(pmap_pt_levels));

    /*
     * Create the initial mappings. The first is for the .boot section
     * and acts as the mandatory identity mapping. The second is the
     * direct physical mapping of physical memory.
     */

    va = vm_page_trunc((uintptr_t)&_boot);
    pa = va;
    size = vm_page_round((uintptr_t)&_boot_end) - va;

    for (i = 0; i < size; i += PAGE_SIZE) {
        vm_ptable_boot_enter(ptable, va, pa, PAGE_SIZE);
        va += PAGE_SIZE;
        pa += PAGE_SIZE;
    }

    directmap_end = bootmem_directmap_end();
    size = directmap_end - PMEM_RAM_START;

    if (size > (PMAP_END_DIRECTMAP_ADDRESS - PMAP_START_DIRECTMAP_ADDRESS)) {
        boot_panic(pmap_panic_directmap_msg);
    }

    va = PMAP_START_DIRECTMAP_ADDRESS;
    pa = PMEM_RAM_START;

    for (i = PMEM_RAM_START; i < directmap_end; i += pgsize) {
        vm_ptable_boot_enter(ptable, va, pa, pgsize);
        va += pgsize;
        pa += pgsize;
    }

    return vm_ptable_boot_root(ptable);
}

#if 0
pmap_pte_t * __boot
pmap_ap_setup_paging(void)
{
    struct pmap_cpu_table *cpu_table;
    struct pmap *pmap;
    unsigned long pgsize;

    pgsize = pmap_boot_get_pgsize();
    pmap_boot_enable_pgext(pgsize);

    pmap = (void *)BOOT_VTOP((uintptr_t)&pmap_kernel_pmap);
    cpu_table = (void *)BOOT_VTOP((uintptr_t)pmap->cpu_tables[boot_ap_id]);

    return (void *)cpu_table->root_ptp_pa;
}

/*
 * Check address range with regard to physical map.
 */
#define pmap_assert_range(pmap, start, end)             \
MACRO_BEGIN                                             \
    assert((start) < (end));                            \
    assert(((end) <= PMAP_START_DIRECTMAP_ADDRESS)      \
           || ((start) >= PMAP_END_DIRECTMAP_ADDRESS)); \
                                                        \
    if ((pmap) == pmap_get_kernel_pmap()) {                        \
        assert(((start) >= PMAP_START_KMEM_ADDRESS)     \
               && ((end) <= PMAP_END_KMEM_ADDRESS));    \
    } else {                                            \
        assert((end) <= PMAP_END_ADDRESS);              \
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
    assert((start < PMAP_END_ADDRESS) || (start >= PMAP_START_KERNEL_ADDRESS));
#endif /* __LP64__ */

    va = start;
    root_ptp_pa = pmap_get_kernel_pmap()->cpu_tables[cpu_id()]->root_ptp_pa;

    do {
#ifdef __LP64__
        /* Handle long mode canonical form */
        if (va == PMAP_END_ADDRESS) {
            va = PMAP_START_KERNEL_ADDRESS;
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
    pmap_walk_vas(PMAP_START_KERNEL_ADDRESS, PMAP_END_KERNEL_ADDRESS,
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
pmap_update_oplist_destroy(struct pmap_update_oplist *oplist)
{
    kmem_cache_free(&pmap_update_oplist_cache, oplist);
}

static struct pmap_update_oplist *
pmap_update_oplist_get(void)
{
    struct pmap_update_oplist *oplist;

    oplist = tcb_get_pmap_update_oplist(tcb_current());
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
#endif

static int __init
pmap_bootstrap(void)
{
#if 0
    struct pmap_cpu_table *cpu_table;
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(pmap_get_kernel_pmap()->cpu_tables); i++) {
        cpu_table = &pmap_kernel_cpu_tables[i];
        pmap_get_kernel_pmap()->cpu_tables[i] = cpu_table;
    }

    cpu_local_assign(pmap_current_ptr, pmap_get_kernel_pmap());

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
    tcb_set_pmap_update_oplist(tcb_current(), &pmap_booter_oplist);

    cpumap_zero(&pmap_booter_cpumap);
    cpumap_set(&pmap_booter_cpumap, 0);

    if (cpu_has_global_pages()) {
        pmap_setup_global_pages();
    }

#endif
    return 0;
}

INIT_OP_DEFINE(pmap_bootstrap,
               INIT_OP_DEP(cpu_setup, true),
               INIT_OP_DEP(mutex_setup, true),
               INIT_OP_DEP(spinlock_setup, true),
               INIT_OP_DEP(syscnt_setup, true),
               INIT_OP_DEP(thread_bootstrap, true));

#if 0
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
    pmap_walk_vas(PMAP_START_ADDRESS, PMAP_END_KERNEL_ADDRESS,
                  pmap_setup_set_ptp_type);
}
#endif

static int __init
pmap_setup(void)
{
#if 0
    pmap_setup_fix_ptps();
    kmem_cache_init(&pmap_cache, "pmap", sizeof(struct pmap), 0, NULL, 0);
    kmem_cache_init(&pmap_update_oplist_cache, "pmap_update_oplist",
                    sizeof(struct pmap_update_oplist), CPU_L1_SIZE,
                    pmap_update_oplist_ctor, 0);
#else
    return 0;
#endif
}

INIT_OP_DEFINE(pmap_setup,
               INIT_OP_DEP(kmem_setup, true),
               INIT_OP_DEP(log_setup, true),
               INIT_OP_DEP(pmap_bootstrap, true),
               INIT_OP_DEP(vm_page_setup, true));

#if 0
void __init
pmap_ap_setup(void)
{
    cpu_local_assign(pmap_current_ptr, pmap_get_kernel_pmap());

    if (cpu_has_global_pages()) {
        cpu_enable_global_pages();
    } else {
        cpu_tlb_flush();
    }
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
        if (va == PMAP_END_ADDRESS) {
            va = PMAP_START_KERNEL_ADDRESS;
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
    struct pmap *kernel_pmap;
    unsigned int level;
    const pmap_pte_t *sptp;
    pmap_pte_t *dptp;

    assert(cpu != 0);

    kernel_pmap = pmap_get_kernel_pmap();
    assert(cpu < ARRAY_SIZE(kernel_pmap->cpu_tables));
    cpu_table = kernel_pmap->cpu_tables[cpu];
    level = PMAP_NR_LEVELS - 1;
    sptp = pmap_ptp_from_pa(kernel_pmap->cpu_tables[cpu_id()]->root_ptp_pa);

    struct vm_page *page;

    page = vm_page_alloc(0, VM_PAGE_SEL_DIRECTMAP, VM_PAGE_PMAP);

    if (page == NULL) {
        panic("pmap: unable to allocate page table root page copy");
    }

    cpu_table->root_ptp_pa = vm_page_to_pa(page);
    dptp = vm_page_direct_ptr(page);

    pmap_copy_cpu_table_recursive(sptp, level, dptp, PMAP_START_ADDRESS);
}

void __init
pmap_mp_setup(void)
{
    char name[THREAD_NAME_SIZE];
    struct pmap_update_oplist *oplist;
    struct thread_attr attr;
    struct pmap_syncer *syncer;
    struct cpumap *cpumap;
    struct tcb *tcb;
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

        tcb = thread_get_tcb(syncer->thread);
        oplist = tcb_get_pmap_update_oplist(tcb);
        tcb_set_pmap_update_oplist(tcb, NULL);
        kmem_cache_free(&pmap_update_oplist_cache, oplist);
    }

    cpumap_destroy(cpumap);

    for (cpu = 1; cpu < cpu_count(); cpu++) {
        pmap_copy_cpu_table(cpu);
    }

    pmap_do_remote_updates = 1;
}

int
pmap_thread_build(struct thread *thread)
{
    struct pmap_update_oplist *oplist;
    int error;

    error = pmap_update_oplist_create(&oplist);

    if (error) {
        return error;
    }

    tcb_set_pmap_update_oplist(thread_get_tcb(thread), oplist);
    return 0;
}

void
pmap_thread_cleanup(struct thread *thread)
{
    struct pmap_update_oplist *oplist;

    oplist = tcb_get_pmap_update_oplist(thread_get_tcb(thread));

    if (oplist) {
        pmap_update_oplist_destroy(oplist);
    }
}
#endif

int
pmap_kextract(uintptr_t va, phys_addr_t *pap)
{
#if 0
    const struct pmap_pt_level *pt_level;
    struct pmap *kernel_pmap;
    pmap_pte_t *ptp, *pte;
    unsigned int level;

    level = PMAP_NR_LEVELS - 1;
    kernel_pmap = pmap_get_kernel_pmap();
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
#else
    (void)va;
    (void)pap;
    return ERROR_AGAIN;
#endif
}

int
pmap_create(struct pmap **pmapp)
{
#if 0
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
#else
    (void)pmapp;
    return ERROR_AGAIN;
#endif
}

#if 0
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

    if (pmap != pmap_get_kernel_pmap()) {
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
                log_warning("pmap: page table page allocation failure");
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
    pte_bits = ((pmap == pmap_get_kernel_pmap()) ? PMAP_PTE_G : PMAP_PTE_US)
               | pmap_prot_table[prot & VM_PROT_ALL];
    pmap_pte_set(pte, pa, pte_bits, pt_level);
    return 0;
}
#endif

int
pmap_enter(struct pmap *pmap, uintptr_t va, phys_addr_t pa,
           int prot, int flags)
{
#if 0
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
#else
    (void)pmap;
    (void)va;
    (void)pa;
    (void)prot;
    (void)flags;
    return ERROR_AGAIN;
#endif
}

#if 0
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
#endif

int
pmap_remove(struct pmap *pmap, uintptr_t va, const struct cpumap *cpumap)
{
#if 0
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
#else
    (void)pmap;
    (void)va;
    (void)cpumap;
    return ERROR_AGAIN;
#endif
}

#if 0
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
    if ((pmap != pmap_current()) && (pmap != pmap_get_kernel_pmap())) {
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
    if ((pmap != pmap_current()) && (pmap != pmap_get_kernel_pmap())) {
        return;
    }

    if (pmap == pmap_get_kernel_pmap()) {
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
#endif

int
pmap_update(struct pmap *pmap)
{
#if 0
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
#else
    (void)pmap;
    return ERROR_AGAIN;
#endif
}

#if 0
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
#endif

void
pmap_load(struct pmap *pmap)
{
#if 0
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
#else
    (void)pmap;
#endif
}
