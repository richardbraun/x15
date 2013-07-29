/*
 * Copyright (c) 2010, 2012, 2013 Richard Braun.
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
#include <kern/cpumap.h>
#include <kern/error.h>
#include <kern/init.h>
#include <kern/kmem.h>
#include <kern/list.h>
#include <kern/macros.h>
#include <kern/mutex.h>
#include <kern/panic.h>
#include <kern/param.h>
#include <kern/spinlock.h>
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
#define PMAP_L1_PTEMAP  PMAP_PTEMAP_BASE
#define PMAP_L2_PTEMAP  (PMAP_L1_PTEMAP + PMAP_LX_INDEX(PMAP_L1_SHIFT))
#define PMAP_L3_PTEMAP  (PMAP_L2_PTEMAP + PMAP_LX_INDEX(PMAP_L2_SHIFT))
#define PMAP_L4_PTEMAP  (PMAP_L3_PTEMAP + PMAP_LX_INDEX(PMAP_L3_SHIFT))

/*
 * Flags related to page protection.
 */
#define PMAP_PTE_PROT_MASK PMAP_PTE_RW

/*
 * Properties of a page translation level.
 */
struct pmap_pt_level {
    unsigned int bits;
    unsigned int shift;
    pmap_pte_t *ptes;   /* PTEs in the recursive mapping */
    unsigned int nr_ptes;
    pmap_pte_t mask;
};

/*
 * Number of mappings to reserve for the pmap module after the kernel.
 *
 * This pool of pure virtual memory can be used to reserve virtual addresses
 * before the VM system is initialized.
 *
 * List of users :
 *  - pmap_zero_mapping (1 page per CPU)
 *  - pmap_ptp_mapping (up to PMAP_NR_RPTPS, 1 per CPU)
 *  - CGA video memory (1 page)
 */
#define PMAP_RESERVED_PAGES (MAX_CPUS                       \
                             + (PMAP_NR_RPTPS * MAX_CPUS)   \
                             + 1)

/*
 * Addresses reserved for temporary mappings.
 */
struct pmap_tmp_mapping {
    struct mutex lock;
    unsigned long va;
};

static struct pmap_tmp_mapping pmap_zero_mappings[MAX_CPUS];
static struct pmap_tmp_mapping pmap_ptp_mappings[MAX_CPUS];

static struct pmap kernel_pmap_store;
struct pmap *kernel_pmap = &kernel_pmap_store;

/*
 * Reserved pages of virtual memory available for early allocation.
 */
static unsigned long pmap_boot_heap __initdata;
static unsigned long pmap_boot_heap_end __initdata;

#ifdef X86_PAE
/*
 * Alignment required on page directory pointer tables.
 */
#define PMAP_PDPT_ALIGN 32

/*
 * "Hidden" kernel root page table for PAE mode.
 */
static pmap_pte_t pmap_kpdpt[PMAP_NR_RPTPS] __aligned(PMAP_PDPT_ALIGN);
#endif /* X86_PAE */

/*
 * Table of page translation properties.
 */
static struct pmap_pt_level pmap_pt_levels[] = {
    { PMAP_L1_BITS, PMAP_L1_SHIFT, PMAP_PTEMAP_BASE, PMAP_L1_NR_PTES, PMAP_L1_MASK },
    { PMAP_L2_BITS, PMAP_L2_SHIFT, PMAP_L2_PTEMAP,   PMAP_L2_NR_PTES, PMAP_L2_MASK },
#if PMAP_NR_LEVELS > 2
    { PMAP_L3_BITS, PMAP_L3_SHIFT, PMAP_L3_PTEMAP,   PMAP_L3_NR_PTES, PMAP_L3_MASK },
#if PMAP_NR_LEVELS > 3
    { PMAP_L4_BITS, PMAP_L4_SHIFT, PMAP_L4_PTEMAP,   PMAP_L4_NR_PTES, PMAP_L4_MASK }
#endif /* PMAP_NR_LEVELS > 3 */
#endif /* PMAP_NR_LEVELS > 2 */
};

/*
 * Table used to convert machine independent protection flags to architecture
 * specific PTE bits.
 */
static pmap_pte_t pmap_prot_table[8];

/*
 * Maximum number of mappings for which individual TLB invalidations can be
 * performed. Global TLB flushes are done beyond this value.
 */
#define PMAP_UPDATE_MAX_MAPPINGS 64

/*
 * Structures related to TLB invalidation.
 */

/*
 * Request sent by a processor.
 */
struct pmap_update_request {
    struct pmap *pmap;
    unsigned long start;
    unsigned long end;
} __aligned(CPU_L1_SIZE);

/*
 * Per processor request, queued on remote processor.
 *
 * A processor receiving such a request is able to locate the invalidation
 * data from the address of the request, without an explicit pointer.
 */
struct pmap_update_cpu_request {
    struct list node;
    int done;
} __aligned(CPU_L1_SIZE);

/*
 * Queue holding update requests from remote processors.
 */
struct pmap_update_queue {
    struct spinlock lock;
    struct list cpu_requests;
} __aligned(CPU_L1_SIZE);

/*
 * Per processor TLB invalidation data.
 */
struct pmap_update_data {
    struct pmap_update_request request;
    struct pmap_update_cpu_request cpu_requests[MAX_CPUS];
    struct cpumap cpumap;
    struct pmap_update_queue queue;
} __aligned(CPU_L1_SIZE);

static struct pmap_update_data pmap_update_data[MAX_CPUS];

/*
 * Global list of physical maps.
 */
static struct mutex pmap_list_lock;
static struct list pmap_list;

static struct kmem_cache pmap_cache;

#ifdef X86_PAE
static struct kmem_cache pmap_pdpt_cache;
#endif /* X86_PAE */

static void __boot
pmap_boot_enter(pmap_pte_t *root_ptp, unsigned long va, phys_addr_t pa)
{
    const struct pmap_pt_level *pt_level, *pt_levels;
    unsigned int level, index;
    pmap_pte_t *pt, *ptp, *pte;

    if (pa != (pa & PMAP_PA_MASK))
        boot_panic("pmap: invalid physical address");

    pt_levels = (void *)BOOT_VTOP((unsigned long)pmap_pt_levels);
    pt = root_ptp;

    for (level = PMAP_NR_LEVELS; level > 1; level--) {
        pt_level = &pt_levels[level - 1];
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

    pte = &pt[(va >> PMAP_L1_SHIFT) & ((1UL << PMAP_L1_BITS) - 1)];
    *pte = (pa & PMAP_PA_MASK) | PMAP_PTE_RW | PMAP_PTE_P;
}

static void __boot
pmap_setup_ptemap(pmap_pte_t *root_ptp)
{
    const struct pmap_pt_level *pt_level, *pt_levels;
    phys_addr_t pa;
    unsigned long va;
    unsigned int i, index;

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
    struct pmap *pmap;
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

    pmap = (void *)BOOT_VTOP((unsigned long)&kernel_pmap_store);
    pmap->root_ptp_pa = (unsigned long)root_ptp;

#ifdef X86_PAE
    pmap->pdpt = pmap_kpdpt;
    pmap->pdpt_pa = BOOT_VTOP((unsigned long)pmap_kpdpt);
    root_ptp = (void *)pmap->pdpt_pa;

    for (i = 0; i < PMAP_NR_RPTPS; i++)
        root_ptp[i] = (pmap->root_ptp_pa + (i * PAGE_SIZE)) | PMAP_PTE_P;

    cpu_enable_pae();
#endif /* X86_PAE */

    return root_ptp;
}

pmap_pte_t * __boot
pmap_ap_setup_paging(void)
{
    struct pmap *pmap;
    pmap_pte_t *root_ptp;

    pmap = (void *)BOOT_VTOP((unsigned long)&kernel_pmap_store);

#ifdef X86_PAE
    root_ptp = (void *)pmap->pdpt_pa;
    cpu_enable_pae();
#else /* X86_PAE */
    root_ptp = (void *)pmap->root_ptp_pa;
#endif /* X86_PAE */

    return root_ptp;
}

/*
 * Helper function for initialization procedures that require post-fixing
 * page properties.
 */
static void __init
pmap_walk_vas(unsigned long start, void (*f)(pmap_pte_t *pte))
{
    const struct pmap_pt_level *pt_level;
    unsigned int level;
    pmap_pte_t *pte;

    assert(vm_page_aligned(start));
#ifdef __LP64__
    assert((start <= VM_MAX_ADDRESS) || (start >= VM_PMAP_PTEMAP_ADDRESS));
#endif /* __LP64__ */

    do {
#ifdef __LP64__
        /* Handle long mode canonical form */
        if (start == ((PMAP_VA_MASK >> 1) + 1))
            start = ~(PMAP_VA_MASK >> 1);
#endif /* __LP64__ */

        for (level = PMAP_NR_LEVELS; level > 0; level--) {
            pt_level = &pmap_pt_levels[level - 1];
            pte = &pt_level->ptes[PMAP_PTEMAP_INDEX(start, pt_level->shift)];

            if (*pte == 0) {
                pte = NULL;
                start = P2END(start, 1UL << pt_level->shift);
                break;
            }
        }

        if (pte == NULL)
            continue;

        f(pte);
        start += PAGE_SIZE;
    } while (start != 0);
}

static void __init
pmap_setup_global_page(pmap_pte_t *pte)
{
    *pte |= PMAP_PTE_G;
}

static void __init
pmap_setup_global_pages(void)
{
    pmap_walk_vas(VM_MAX_KERNEL_ADDRESS, pmap_setup_global_page);
    pmap_pt_levels[0].mask |= PMAP_PTE_G;
    cpu_enable_global_pages();
}

void __init
pmap_bootstrap(void)
{
    unsigned int i;

    mutex_init(&kernel_pmap->lock);
    cpumap_zero(&kernel_pmap->cpumap);
    cpumap_set(&kernel_pmap->cpumap, 0);
    cpu_percpu_set_pmap(kernel_pmap);

    pmap_boot_heap = (unsigned long)&_end;
    pmap_boot_heap_end = pmap_boot_heap + (PMAP_RESERVED_PAGES * PAGE_SIZE);

    pmap_prot_table[VM_PROT_NONE] = 0;
    pmap_prot_table[VM_PROT_READ] = 0;
    pmap_prot_table[VM_PROT_WRITE] = PMAP_PTE_RW;
    pmap_prot_table[VM_PROT_WRITE | VM_PROT_READ] = PMAP_PTE_RW;
    pmap_prot_table[VM_PROT_EXECUTE] = 0;
    pmap_prot_table[VM_PROT_EXECUTE | VM_PROT_READ] = 0;
    pmap_prot_table[VM_PROT_EXECUTE | VM_PROT_WRITE] = PMAP_PTE_RW;
    pmap_prot_table[VM_PROT_ALL] = PMAP_PTE_RW;

    for (i = 0; i < MAX_CPUS; i++) {
        mutex_init(&pmap_zero_mappings[i].lock);
        pmap_zero_mappings[i].va = pmap_bootalloc(1);

        mutex_init(&pmap_ptp_mappings[i].lock);
        pmap_ptp_mappings[i].va = pmap_bootalloc(PMAP_NR_RPTPS);

        spinlock_init(&pmap_update_data[i].queue.lock);
        list_init(&pmap_update_data[i].queue.cpu_requests);
    }

    mutex_init(&pmap_list_lock);
    list_init(&pmap_list);
    list_insert_tail(&pmap_list, &kernel_pmap->node);

    pmap_protect(kernel_pmap, (unsigned long)&_text, (unsigned long)&_rodata,
                 VM_PROT_READ | VM_PROT_EXECUTE);
    pmap_protect(kernel_pmap, (unsigned long)&_rodata, (unsigned long)&_data,
                 VM_PROT_READ);

    if (cpu_has_global_pages())
        pmap_setup_global_pages();

    cpu_tlb_flush();
}

void __init
pmap_ap_bootstrap(void)
{
    cpumap_set(&kernel_pmap->cpumap, cpu_id());
    cpu_percpu_set_pmap(kernel_pmap);

    if (cpu_has_global_pages())
        cpu_enable_global_pages();
}

unsigned long __init
pmap_bootalloc(unsigned int nr_pages)
{
    unsigned long page;
    size_t size;

    assert(nr_pages > 0);

    size = nr_pages * PAGE_SIZE;

    assert((pmap_boot_heap + size) > pmap_boot_heap);
    assert((pmap_boot_heap + size) <= pmap_boot_heap_end);

    page = pmap_boot_heap;
    pmap_boot_heap += size;
    return page;
}

/*
 * Check address range with regard to physical map.
 *
 * Note that there is no addressing restriction on the kernel pmap.
 */
#define pmap_assert_range(pmap, start, end)                         \
MACRO_BEGIN                                                         \
    assert(vm_page_aligned(start) && vm_page_aligned(end));         \
    assert((start) < (end));                                        \
    assert(((pmap) == kernel_pmap) || ((end) <= VM_MAX_ADDRESS));   \
MACRO_END

static inline void
pmap_pte_set(pmap_pte_t *pte, phys_addr_t pa, pmap_pte_t pte_bits,
             unsigned int level)
{
    assert(level > 0);
    *pte = ((pa & PMAP_PA_MASK) | PMAP_PTE_P | pte_bits)
           & pmap_pt_levels[level - 1].mask;
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

    pte = PMAP_PTEMAP_BASE + PMAP_PTEMAP_INDEX(va, PMAP_L1_SHIFT);
    pmap_pte_set(pte, pa, PMAP_PTE_G | pmap_prot_table[prot & VM_PROT_ALL], 1);
}

static void
pmap_kremove(unsigned long start, unsigned long end)
{
    pmap_pte_t *pte;

    pmap_assert_range(kernel_pmap, start, end);

    while (start < end) {
        pte = PMAP_PTEMAP_BASE + PMAP_PTEMAP_INDEX(start, PMAP_L1_SHIFT);
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
pmap_map_ptp(phys_addr_t pa)
{
    struct pmap_tmp_mapping *ptp_mapping;
    unsigned long va;
    unsigned int i, offset;

    thread_pin();
    ptp_mapping  = &pmap_ptp_mappings[cpu_id()];
    mutex_lock(&ptp_mapping->lock);

    for (i = 0; i < PMAP_NR_RPTPS; i++) {
        offset = i * PAGE_SIZE;
        va = ptp_mapping->va + offset;
        pmap_kenter(va, pa + offset, VM_PROT_READ | VM_PROT_WRITE);
        cpu_tlb_flush_va(va);
    }

    return ptp_mapping;
}

static void
pmap_unmap_ptp(struct pmap_tmp_mapping *ptp_mapping)
{
    unsigned long va;
    unsigned int i;

    assert(thread_pinned());
    mutex_assert_locked(&ptp_mapping->lock);

    va = ptp_mapping->va;
    pmap_kremove(va, va + (PMAP_NR_RPTPS * PAGE_SIZE));

    for (i = 0; i < PMAP_NR_RPTPS; i++)
        cpu_tlb_flush_va(va + (i * PAGE_SIZE));

    mutex_unlock(&ptp_mapping->lock);
    thread_unpin();
}

static void
pmap_protect_ptemap(unsigned long start, unsigned long end, int prot)
{
    pmap_pte_t *pte, flags;

    flags = pmap_prot_table[prot & VM_PROT_ALL];

    while (start < end) {
        pte = PMAP_PTEMAP_BASE + PMAP_PTEMAP_INDEX(start, PMAP_L1_SHIFT);
        *pte = (*pte & ~PMAP_PTE_PROT_MASK) | flags;
        start += PAGE_SIZE;
    }
}

void
pmap_protect(struct pmap *pmap, unsigned long start, unsigned long end,
             int prot)
{
    pmap_assert_range(pmap, start, end);

    if ((pmap == kernel_pmap) || (pmap == pmap_current())) {
        pmap_protect_ptemap(start, end, prot);
        return;
    }

    /* TODO Complete pmap_protect() */
    panic("pmap: pmap_protect not completely implemented yet");
}

static phys_addr_t
pmap_extract_ptemap(unsigned long va)
{
    const struct pmap_pt_level *pt_level;
    unsigned int level;
    pmap_pte_t *pte;

    for (level = PMAP_NR_LEVELS; level > 0; level--) {
        pt_level = &pmap_pt_levels[level - 1];
        pte = &pt_level->ptes[PMAP_PTEMAP_INDEX(va, pt_level->shift)];

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

    /* TODO Complete pmap_extract() */
    panic("pmap: pmap_extract not completely implemented yet");
}

static void
pmap_update_local(struct pmap *pmap, unsigned long start, unsigned long end)
{
    if ((pmap != pmap_current()) && (pmap != kernel_pmap))
        return;

    if (vm_page_atop(end - start) > PMAP_UPDATE_MAX_MAPPINGS) {
        if (pmap == kernel_pmap)
            cpu_tlb_flush_all();
        else
            cpu_tlb_flush();
    } else {
        while (start < end) {
            cpu_tlb_flush_va(start);
            start += PAGE_SIZE;
        }
    }
}

void
pmap_update(struct pmap *pmap, unsigned long start, unsigned long end)
{
    struct pmap_update_data *pud;
    struct pmap_update_queue *queue;
    unsigned long flags;
    unsigned int cpu;
    int i;

    pmap_assert_range(pmap, start, end);

    if (cpu_count() == 1) {
        pmap_update_local(pmap, start, end);
        return;
    }

    assert(cpu_intr_enabled());

    thread_preempt_disable();

    cpu = cpu_id();
    pud = &pmap_update_data[cpu];
    pud->request.pmap = pmap;
    pud->request.start = start;
    pud->request.end = end;

    cpumap_copy(&pud->cpumap, &pmap->cpumap);

    cpumap_for_each(&pud->cpumap, i)
        if ((unsigned int)i != cpu) {
            pud->cpu_requests[i].done = 0;
            queue = &pmap_update_data[i].queue;

            spinlock_lock_intr_save(&queue->lock, &flags);
            list_insert_tail(&queue->cpu_requests, &pud->cpu_requests[i].node);
            spinlock_unlock_intr_restore(&queue->lock, flags);
        }

    if (pmap == kernel_pmap)
        lapic_ipi_broadcast(TRAP_PMAP_UPDATE);
    else
        cpumap_for_each(&pud->cpumap, i)
            if ((unsigned int)i != cpu)
                lapic_ipi_send(i, TRAP_PMAP_UPDATE);

    pmap_update_local(pmap, start, end);

    cpumap_for_each(&pud->cpumap, i)
        if ((unsigned int)i != cpu)
            while (!pud->cpu_requests[i].done)
                cpu_pause();

    thread_preempt_enable();
}

void
pmap_update_intr(struct trap_frame *frame)
{
    struct pmap_update_cpu_request *cpu_request, *array;
    struct pmap_update_data *pud;
    struct list cpu_requests, *node;
    unsigned int cpu;

    (void)frame;

    lapic_eoi();

    cpu = cpu_id();
    pud = &pmap_update_data[cpu];

    spinlock_lock(&pud->queue.lock);
    list_set_head(&cpu_requests, &pud->queue.cpu_requests);
    list_init(&pud->queue.cpu_requests);
    spinlock_unlock(&pud->queue.lock);

    while (!list_empty(&cpu_requests)) {
        node = list_first(&cpu_requests);
        cpu_request = list_entry(node, struct pmap_update_cpu_request, node);
        list_remove(&cpu_request->node);

        array = cpu_request - cpu;
        pud = structof(array, struct pmap_update_data, cpu_requests);
        pmap_update_local(pud->request.pmap, pud->request.start,
                          pud->request.end);
        cpu_request->done = 1;
    }
}

#ifdef X86_PAE
static unsigned long
pmap_pdpt_alloc(size_t slab_size)
{
    struct vm_page *page;
    unsigned long va, start, end;
    int error;

    va = vm_kmem_alloc_va(slab_size);

    if (va == 0)
        return 0;

    for (start = va, end = va + slab_size; start < end; start += PAGE_SIZE) {
        page = vm_page_alloc_seg(0, VM_PAGE_SEG_NORMAL, VM_PAGE_PMAP);

        if (page == NULL)
            goto error_page;

        error = pmap_enter(kernel_pmap, start, vm_page_to_pa(page),
                           VM_PROT_READ | VM_PROT_WRITE);

        if (error)
            goto error_enter;
    }

    pmap_update(kernel_pmap, va, end);
    return va;

error_enter:
    vm_page_free(page, 0);
error_page:
    vm_kmem_free(va, slab_size);
    return 0;
}
#endif /* X86_PAE */

static void __init
pmap_setup_inc_nr_ptes(pmap_pte_t *pte)
{
    struct vm_page *page;

    page = vm_kmem_lookup_page(vm_page_trunc((unsigned long)pte));
    assert(page != NULL);

    /*
     * PTPs of type VM_PAGE_PMAP were allocated after the VM system was
     * initialized. Their PTEs count doesn't need fixing.
     */
    if (vm_page_type(page) != VM_PAGE_PMAP) {
        assert(vm_page_type(page) == VM_PAGE_RESERVED);
        page->pmap_page.nr_ptes++;
    }
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
    /*
     * This call count entries at the lowest level. Accounting on upper PTPs
     * is done when walking the recursive mapping.
     */
    pmap_walk_vas(0, pmap_setup_inc_nr_ptes);

    /* Now that accounting is finished, properly fix up PTPs types */
    pmap_walk_vas(0, pmap_setup_set_ptp_type);
}

void __init
pmap_setup(void)
{
    pmap_setup_count_ptes();

    kmem_cache_init(&pmap_cache, "pmap", sizeof(struct pmap),
                    0, NULL, NULL, NULL, 0);

#ifdef X86_PAE
    kmem_cache_init(&pmap_pdpt_cache, "pmap_pdpt",
                    PMAP_NR_RPTPS * sizeof(pmap_pte_t), PMAP_PDPT_ALIGN,
                    NULL, pmap_pdpt_alloc, NULL, 0);
#endif /* X86_PAE */
}


int
pmap_create(struct pmap **pmapp)
{
    const struct pmap_pt_level *pt_level;
    struct pmap_tmp_mapping *ptp_mapping;
    struct vm_page *root_pages;
    struct pmap *pmap;
    pmap_pte_t *pt, *kpt;
    phys_addr_t pa;
    unsigned long va;
    unsigned int i, index;
    int error;

    pmap = kmem_cache_alloc(&pmap_cache);

    if (pmap == NULL) {
        error = ERROR_NOMEM;
        goto error_pmap;
    }

    root_pages = vm_page_alloc(PMAP_RPTP_ORDER, VM_PAGE_PMAP);

    if (root_pages == NULL) {
        error = ERROR_NOMEM;
        goto error_pages;
    }

    pmap->root_ptp_pa = vm_page_to_pa(root_pages);

#ifdef X86_PAE
    pmap->pdpt = kmem_cache_alloc(&pmap_pdpt_cache);

    if (pmap->pdpt == NULL) {
        error = ERROR_NOMEM;
        goto error_pdpt;
    }

    va = (unsigned long)pmap->pdpt;
    assert(P2ALIGNED(va, PMAP_PDPT_ALIGN));

    for (i = 0; i < PMAP_NR_RPTPS; i++)
        pmap->pdpt[i] = (pmap->root_ptp_pa + (i * PAGE_SIZE)) | PMAP_PTE_P;

    pa = pmap_extract_ptemap(va) + (va & PAGE_MASK);
    assert(pa < VM_PAGE_NORMAL_LIMIT);
    pmap->pdpt_pa = (unsigned long)pa;
#endif /* X86_PAE */

    pt_level = &pmap_pt_levels[PMAP_NR_LEVELS - 1];
    kpt = pt_level->ptes;
    index = PMAP_PTEMAP_INDEX(VM_PMAP_PTEMAP_ADDRESS, pt_level->shift);

    mutex_init(&pmap->lock);
    cpumap_zero(&pmap->cpumap);

    /* The pmap list lock also protects the shared root page table entries */
    mutex_lock(&pmap_list_lock);
    ptp_mapping = pmap_map_ptp(pmap->root_ptp_pa);
    pt = (pmap_pte_t *)ptp_mapping->va;

    memset(pt, 0, index * sizeof(pmap_pte_t));
    index += PMAP_NR_RPTPS;
    memcpy(&pt[index], &kpt[index], (pt_level->nr_ptes - index)
                                    * sizeof(pmap_pte_t));

    for (i = 0; i < PMAP_NR_RPTPS; i++) {
        va = VM_PMAP_PTEMAP_ADDRESS + (i * (1UL << pt_level->shift));
        index = (va >> pt_level->shift) & ((1UL << pt_level->bits) - 1);
        pa = pmap->root_ptp_pa + (i * PAGE_SIZE);
        pt[index] = (pa | PMAP_PTE_RW | PMAP_PTE_P) & pt_level->mask;
    }

    pmap_unmap_ptp(ptp_mapping);
    list_insert_tail(&pmap_list, &pmap->node);
    mutex_unlock(&pmap_list_lock);

    *pmapp = pmap;
    return 0;

#ifdef X86_PAE
error_pdpt:
    vm_page_free(root_pages, PMAP_RPTP_ORDER);
#endif /* X86_PAE */
error_pages:
    kmem_cache_free(&pmap_cache, pmap);
error_pmap:
    return error;
}

static void
pmap_enter_ptemap_sync_kernel(unsigned int index)
{
    const struct pmap_pt_level *pt_level;
    struct pmap_tmp_mapping *ptp_mapping;
    struct pmap *pmap, *current;
    pmap_pte_t *root_ptp;

    pt_level = &pmap_pt_levels[PMAP_NR_LEVELS - 1];
    current = pmap_current();

    mutex_lock(&pmap_list_lock);

    list_for_each_entry(&pmap_list, pmap, node) {
        if (pmap == current)
            continue;

        ptp_mapping = pmap_map_ptp(pmap->root_ptp_pa);
        root_ptp = (pmap_pte_t *)ptp_mapping->va;
        assert(root_ptp[index] == 0);
        root_ptp[index] = pt_level->ptes[index];
        pmap_unmap_ptp(ptp_mapping);
    }

    mutex_unlock(&pmap_list_lock);

    /*
     * Since kernel page table pages can only be added, it is certain there
     * could be no previous translation for them in the recursive mapping.
     * As a result, there is no need to flush TLBs.
     */
}

static int
pmap_enter_ptemap(struct pmap *pmap, unsigned long va, phys_addr_t pa, int prot)
{
    const struct pmap_pt_level *pt_level;
    struct vm_page *page;
    unsigned int level, index;
    pmap_pte_t *pte, pte_bits;
    phys_addr_t ptp_pa;

    pte_bits = PMAP_PTE_RW;

    /*
     * The recursive mapping is protected from user access by not setting
     * the U/S bit when inserting the root page table into itself.
     */
    if (pmap != kernel_pmap)
        pte_bits |= PMAP_PTE_US;

    for (level = PMAP_NR_LEVELS; level > 1; level--) {
        pt_level = &pmap_pt_levels[level - 1];
        index = PMAP_PTEMAP_INDEX(va, pt_level->shift);
        pte = &pt_level->ptes[index];

        if (*pte != 0)
            continue;

        if (!vm_page_ready) {
            assert(pmap == kernel_pmap);
            ptp_pa = vm_page_bootalloc();
        } else {
            page = vm_page_alloc(0, VM_PAGE_PMAP);

            /* TODO Release page table pages */
            if (page == NULL)
                return ERROR_NOMEM;

            ptp_pa = vm_page_to_pa(page);
        }

        pmap_zero_page(ptp_pa);
        pmap_pte_set(pte, ptp_pa, pte_bits, level);

        if ((pmap == kernel_pmap) && (level == PMAP_NR_LEVELS))
            pmap_enter_ptemap_sync_kernel(index);

    }

    pte = PMAP_PTEMAP_BASE + PMAP_PTEMAP_INDEX(va, PMAP_L1_SHIFT);
    pte_bits = ((pmap == kernel_pmap) ? PMAP_PTE_G : PMAP_PTE_US)
               | pmap_prot_table[prot & VM_PROT_ALL];
    pmap_pte_set(pte, pa, pte_bits, 1);
    return 0;
}

int
pmap_enter(struct pmap *pmap, unsigned long va, phys_addr_t pa, int prot)
{
    pmap_assert_range(pmap, va, va + PAGE_SIZE);

    if ((pmap == kernel_pmap) || (pmap == pmap_current()))
        return pmap_enter_ptemap(pmap, va, pa, prot);

    /* TODO Complete pmap_enter() */
    panic("pmap: pmap_enter not completely implemented yet");
}

static void
pmap_remove_ptemap(struct pmap *pmap, unsigned long start, unsigned long end)
{
    pmap_pte_t *pte;

    pmap_assert_range(pmap, start, end);

    while (start < end) {
        pte = PMAP_PTEMAP_BASE + PMAP_PTEMAP_INDEX(start, PMAP_L1_SHIFT);
        pmap_pte_clear(pte);
        start += PAGE_SIZE;
    }

    /* TODO Release page table pages */
}

void
pmap_remove(struct pmap *pmap, unsigned long start, unsigned long end)
{
    if ((pmap == kernel_pmap) || (pmap == pmap_current())) {
        pmap_remove_ptemap(pmap, start, end);
        return;
    }

    /* TODO Complete pmap_remove() */
    panic("pmap: pmap_remove not completely implemented yet");
}

void
pmap_load(struct pmap *pmap)
{
    struct pmap *prev;
    unsigned int cpu;

    assert(!cpu_intr_enabled());
    assert(!thread_preempt_enabled());

    prev = pmap_current();

    if (prev == pmap)
        return;

    cpu = cpu_id();

    /*
     * The kernel pmap is considered always loaded on every processor. As a
     * result, its CPU map is never changed. In addition, don't bother
     * flushing the TLB when switching to a kernel thread, which results in
     * a form of lazy TLB invalidation.
     *
     * TODO As an exception, force switching when the currently loaded pmap
     * is about to be destroyed.
     */
    if (prev == kernel_pmap) {
        cpu_percpu_set_pmap(pmap);
        cpumap_set_atomic(&pmap->cpumap, cpu);
    } else if (pmap == kernel_pmap) {
        cpumap_clear_atomic(&prev->cpumap, cpu);
        cpu_percpu_set_pmap(kernel_pmap);
        return;
    } else {
        cpumap_clear_atomic(&prev->cpumap, cpu);
        cpu_percpu_set_pmap(pmap);
        cpumap_set_atomic(&pmap->cpumap, cpu);
    }

#ifdef X86_PAE
    cpu_set_cr3(pmap->pdpt_pa);
#else /* X86_PAE */
    cpu_set_cr3(pmap->root_ptp_pa);
#endif /* X86_PAE */
}
