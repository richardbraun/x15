/*
 * Copyright (c) 2010, 2012 Richard Braun.
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
#include <kern/error.h>
#include <kern/init.h>
#include <kern/kmem.h>
#include <kern/list.h>
#include <kern/macros.h>
#include <kern/panic.h>
#include <kern/param.h>
#include <kern/spinlock.h>
#include <kern/stddef.h>
#include <kern/string.h>
#include <kern/thread.h>
#include <kern/types.h>
#include <machine/atomic.h>
#include <machine/biosmem.h>
#include <machine/boot.h>
#include <machine/cpu.h>
#include <machine/lapic.h>
#include <machine/mb.h>
#include <machine/pmap.h>
#include <machine/trap.h>
#include <vm/vm_kmem.h>
#include <vm/vm_page.h>
#include <vm/vm_prot.h>
#include <vm/vm_phys.h>

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
 * Number of pages to reserve for the pmap module after the kernel.
 *
 * This pool of pure virtual memory can be used to reserve virtual addresses
 * before the VM system is initialized.
 *
 * List of users :
 *  - pmap_zero_va (1 page)
 *  - pmap_pt_va (up to PMAP_NR_RPTPS, 1 per CPU)
 *  - CGA video memory (1 page)
 */
#define PMAP_RESERVED_PAGES (1 + (PMAP_NR_RPTPS * MAX_CPUS) + 1)

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
 * Maximum mappable kernel address.
 */
static unsigned long pmap_kernel_limit;

/*
 * Table of page translation properties.
 */
static struct pmap_pt_level pmap_pt_levels[] = {
    { PMAP_L1_BITS, PMAP_L1_SHIFT, PMAP_PTEMAP_BASE, PMAP_L2_NR_PTES, PMAP_L1_MASK },
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
 * Special addresses for temporary mappings.
 */
static struct spinlock pmap_zero_va_lock;
static unsigned long pmap_zero_va;

static struct {
    struct spinlock lock;
    unsigned long va;
} pmap_pt_vas[MAX_CPUS];

/*
 * Shared variables used by the inter-processor update functions.
 */
static unsigned long pmap_update_start;
static unsigned long pmap_update_end;
static struct spinlock pmap_update_lock;

/*
 * There is strong bouncing on this counter so give it its own cache line.
 */
static struct {
    volatile unsigned long count __aligned(CPU_L1_SIZE);
} pmap_nr_updates;

/*
 * Global list of physical maps.
 */
static struct spinlock pmap_list_lock;
static struct list pmap_list;

static struct kmem_cache pmap_cache;

#ifdef X86_PAE
static struct kmem_cache pmap_pdpt_cache;
#endif /* X86_PAE */

static void __boot
pmap_boot_enter(pmap_pte_t *root_pt, unsigned long va, phys_addr_t pa)
{
    const struct pmap_pt_level *pt_level, *pt_levels;
    unsigned int level, index;
    pmap_pte_t *pt, *ptp, *pte;

    if (pa != (pa & PMAP_PA_MASK))
        boot_panic("pmap: invalid physical address");

    pt_levels = (void *)BOOT_VTOP((unsigned long)pmap_pt_levels);
    pt = root_pt;

    for (level = PMAP_NR_LEVELS; level > 1; level--) {
        pt_level = &pt_levels[level - 1];
        index = (va >> pt_level->shift) & ((1UL << pt_level->bits) - 1);
        pte = &pt[index];

        if (*pte & PMAP_PTE_P)
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
pmap_setup_ptemap(pmap_pte_t *root_pt)
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
        pa = (unsigned long)root_pt + (i * PAGE_SIZE);
        root_pt[index] = (pa | PMAP_PTE_RW | PMAP_PTE_P) & pt_level->mask;
    }
}

pmap_pte_t * __boot
pmap_setup_paging(void)
{
    struct pmap *pmap;
    pmap_pte_t *root_pt;
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

    root_pt = biosmem_bootalloc(PMAP_NR_RPTPS);

    va = vm_page_trunc((unsigned long)&_boot);
    pa = va;
    size = vm_page_round((unsigned long)&_eboot) - va;

    for (i = 0; i < size; i += PAGE_SIZE) {
        pmap_boot_enter(root_pt, va, pa);
        va += PAGE_SIZE;
        pa += PAGE_SIZE;
    }

    va = vm_page_trunc((unsigned long)&_init);
    pa = BOOT_VTOP(va);
    size = vm_page_round((unsigned long)&_end) - va;

    for (i = 0; i < size; i += PAGE_SIZE) {
        pmap_boot_enter(root_pt, va, pa);
        va += PAGE_SIZE;
        pa += PAGE_SIZE;
    }

    for (i = 0; i < PMAP_RESERVED_PAGES; i++) {
        pmap_boot_enter(root_pt, va, 0);
        va += PAGE_SIZE;
    }

    pmap_setup_ptemap(root_pt);

    pmap = (void *)BOOT_VTOP((unsigned long)&kernel_pmap_store);
    pmap->root_pt = (unsigned long)root_pt;

#ifdef X86_PAE
    pmap->pdpt = pmap_kpdpt;
    pmap->pdpt_pa = BOOT_VTOP((unsigned long)pmap_kpdpt);
    root_pt = (void *)pmap->pdpt_pa;

    for (i = 0; i < PMAP_NR_RPTPS; i++)
        root_pt[i] = (pmap->root_pt + (i * PAGE_SIZE)) | PMAP_PTE_P;

    cpu_enable_pae();
#endif /* X86_PAE */

    return root_pt;
}

pmap_pte_t * __boot
pmap_ap_setup_paging(void)
{
    struct pmap *pmap;
    pmap_pte_t *root_pt;

    pmap = (void *)BOOT_VTOP((unsigned long)&kernel_pmap_store);

#ifdef X86_PAE
    root_pt = (void *)pmap->pdpt_pa;
    cpu_enable_pae();
#else /* X86_PAE */
    root_pt = (void *)pmap->root_pt;
#endif /* X86_PAE */

    return root_pt;
}

static void __init
pmap_setup_global_pages(void)
{
    const struct pmap_pt_level *pt_level;
    unsigned long va;
    unsigned int level;
    pmap_pte_t *pte;

    va = VM_MAX_KERNEL_ADDRESS;

    while (va >= VM_MAX_KERNEL_ADDRESS) {
        for (level = PMAP_NR_LEVELS; level > 0; level--) {
            pt_level = &pmap_pt_levels[level - 1];
            pte = &pt_level->ptes[PMAP_PTEMAP_INDEX(va, pt_level->shift)];

            if (!(*pte & PMAP_PTE_P)) {
                pte = NULL;
                va = P2END(va, 1UL << pt_level->shift);
                break;
            }
        }

        if (pte == NULL)
            continue;

        *pte |= PMAP_PTE_G;
        va += PAGE_SIZE;
    }

    pmap_pt_levels[0].mask |= PMAP_PTE_G;
    cpu_enable_global_pages();
}

void __init
pmap_bootstrap(void)
{
    unsigned int i;

    spinlock_init(&kernel_pmap->lock);
    cpu_percpu_set_pmap(kernel_pmap);

    pmap_boot_heap = (unsigned long)&_end;
    pmap_boot_heap_end = pmap_boot_heap + (PMAP_RESERVED_PAGES * PAGE_SIZE);

    pmap_kernel_limit = VM_MIN_KERNEL_ADDRESS;

    pmap_prot_table[VM_PROT_NONE] = 0;
    pmap_prot_table[VM_PROT_READ] = 0;
    pmap_prot_table[VM_PROT_WRITE] = PMAP_PTE_RW;
    pmap_prot_table[VM_PROT_WRITE | VM_PROT_READ] = PMAP_PTE_RW;
    pmap_prot_table[VM_PROT_EXECUTE] = 0;
    pmap_prot_table[VM_PROT_EXECUTE | VM_PROT_READ] = 0;
    pmap_prot_table[VM_PROT_EXECUTE | VM_PROT_WRITE] = PMAP_PTE_RW;
    pmap_prot_table[VM_PROT_ALL] = PMAP_PTE_RW;

    spinlock_init(&pmap_zero_va_lock);
    pmap_zero_va = pmap_bootalloc(1);

    for (i = 0; i < MAX_CPUS; i++) {
        spinlock_init(&pmap_pt_vas[i].lock);
        pmap_pt_vas[i].va = pmap_bootalloc(PMAP_NR_RPTPS);
    }

    spinlock_init(&pmap_update_lock);

    spinlock_init(&pmap_list_lock);
    list_init(&pmap_list);
    list_insert_tail(&pmap_list, &kernel_pmap->node);

    pmap_kprotect((unsigned long)&_text, (unsigned long)&_rodata,
                  VM_PROT_READ | VM_PROT_EXECUTE);
    pmap_kprotect((unsigned long)&_rodata, (unsigned long)&_data, VM_PROT_READ);

    if (cpu_has_global_pages())
        pmap_setup_global_pages();

    cpu_tlb_flush();
}

void __init
pmap_ap_bootstrap(void)
{
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

unsigned long
pmap_klimit(void)
{
    return pmap_kernel_limit;
}

static void
pmap_zero_page(phys_addr_t pa)
{
    /*
     * This function is currently only used by pmap_kgrow, which is already
     * protected from concurrent execution. Grab a lock for safety. Disable
     * migration to remove the need to globally flush the TLB.
     */

    thread_pin();
    spinlock_lock(&pmap_zero_va_lock);
    pmap_kenter(pmap_zero_va, pa);
    cpu_tlb_flush_va(pmap_zero_va);
    memset((void *)pmap_zero_va, 0, PAGE_SIZE);
    spinlock_unlock(&pmap_zero_va_lock);
    thread_unpin();
}

static unsigned long
pmap_map_pt(phys_addr_t pa)
{
    unsigned long va, base;
    unsigned int i, cpu, offset;

    thread_pin();
    cpu = cpu_id();
    base = pmap_pt_vas[cpu].va;
    spinlock_lock(&pmap_pt_vas[cpu].lock);

    for (i = 0; i < PMAP_NR_RPTPS; i++) {
        offset = i * PAGE_SIZE;
        va = base + offset;
        pmap_kenter(va, pa + offset);
        cpu_tlb_flush_va(va);
    }

    return base;
}

static void
pmap_unmap_pt(void)
{
    unsigned long base;
    unsigned int i, cpu;

    assert(thread_pinned());

    cpu = cpu_id();
    base = pmap_pt_vas[cpu].va;
    pmap_kremove(base, base + (PMAP_NR_RPTPS * PAGE_SIZE));

    for (i = 0; i < PMAP_NR_RPTPS; i++)
        cpu_tlb_flush_va(base + (i * PAGE_SIZE));

    spinlock_unlock(&pmap_pt_vas[cpu].lock);
    thread_unpin();
}

static void
pmap_kgrow_update_pmaps(unsigned int index)
{
    const struct pmap_pt_level *pt_level;
    struct pmap *pmap, *current;
    pmap_pte_t *root_pt;

    pt_level = &pmap_pt_levels[PMAP_NR_LEVELS - 1];
    current = pmap_current();

    spinlock_lock(&pmap_list_lock);

    list_for_each_entry(&pmap_list, pmap, node) {
        if (pmap == current)
            continue;

        root_pt = (pmap_pte_t *)pmap_map_pt(pmap->root_pt);
        root_pt[index] = pt_level->ptes[index];
        pmap_unmap_pt();
    }

    spinlock_unlock(&pmap_list_lock);
}

void
pmap_kgrow(unsigned long end)
{
    const struct pmap_pt_level *pt_level, *pt_lower_level;
    struct vm_page *page;
    unsigned long start, va, lower_pt_va;
    unsigned int level, index, lower_index;
    pmap_pte_t *pte, *lower_pt;
    phys_addr_t pa;

    start = pmap_kernel_limit;
    end = P2END(end, 1UL << PMAP_L2_SHIFT) - 1;
    assert(start < end);

    for (level = PMAP_NR_LEVELS; level > 1; level--) {
        pt_level = &pmap_pt_levels[level - 1];
        pt_lower_level = &pmap_pt_levels[level - 2];

        for (va = start; va <= end; va = P2END(va, 1UL << pt_level->shift)) {
            index = PMAP_PTEMAP_INDEX(va, pt_level->shift);
            pte = &pt_level->ptes[index];

            if (!(*pte & PMAP_PTE_P)) {
                if (!vm_phys_ready)
                    pa = vm_phys_bootalloc();
                else {
                    page = vm_phys_alloc(0);

                    if (page == NULL)
                        panic("pmap: no page available to grow kernel space");

                    pa = vm_page_to_pa(page);
                }

                pmap_zero_page(pa);
                *pte = (pa | PMAP_PTE_G | PMAP_PTE_RW | PMAP_PTE_P)
                       & pt_level->mask;

                if (level == PMAP_NR_LEVELS)
                    pmap_kgrow_update_pmaps(index);

                lower_index = PMAP_PTEMAP_INDEX(va, pt_lower_level->shift);
                lower_pt = &pt_lower_level->ptes[lower_index];
                lower_pt_va = (unsigned long)lower_pt;
                pmap_kupdate(lower_pt_va, lower_pt_va + PAGE_SIZE);
            }
        }
    }

    pmap_kernel_limit = end + 1;
}

void
pmap_kenter(unsigned long va, phys_addr_t pa)
{
    pmap_pte_t *pte;

    pte = PMAP_PTEMAP_BASE + PMAP_PTEMAP_INDEX(va, PMAP_L1_SHIFT);
    *pte = ((pa & PMAP_PA_MASK) | PMAP_PTE_G | PMAP_PTE_RW | PMAP_PTE_P)
           & pmap_pt_levels[0].mask;
}

void
pmap_kremove(unsigned long start, unsigned long end)
{
    pmap_pte_t *pte;

    while (start < end) {
        pte = PMAP_PTEMAP_BASE + PMAP_PTEMAP_INDEX(start, PMAP_L1_SHIFT);
        *pte = 0;
        start += PAGE_SIZE;
    }
}

void
pmap_kprotect(unsigned long start, unsigned long end, int prot)
{
    pmap_pte_t *pte, flags;

    flags = pmap_prot_table[prot & VM_PROT_ALL];

    while (start < end) {
        pte = PMAP_PTEMAP_BASE + PMAP_PTEMAP_INDEX(start, PMAP_L1_SHIFT);
        *pte = (*pte & ~PMAP_PTE_PROT_MASK) | flags;
        start += PAGE_SIZE;
    }
}

phys_addr_t
pmap_kextract(unsigned long va)
{
    const struct pmap_pt_level *pt_level;
    unsigned int level;
    pmap_pte_t *pte;

    for (level = PMAP_NR_LEVELS; level > 0; level--) {
        pt_level = &pmap_pt_levels[level - 1];
        pte = &pt_level->ptes[PMAP_PTEMAP_INDEX(va, pt_level->shift)];

        if (!(*pte & PMAP_PTE_P))
            return 0;
    }

    return *pte & PMAP_PA_MASK;
}

static void
pmap_kupdate_local(unsigned long start, unsigned long end)
{
    while (start < end) {
        cpu_tlb_flush_va(start);
        start += PAGE_SIZE;
    }
}

void
pmap_kupdate(unsigned long start, unsigned long end)
{
    unsigned int nr_cpus;

    nr_cpus = cpu_count();

    if (nr_cpus == 1) {
        pmap_kupdate_local(start, end);
        return;
    }

    spinlock_lock(&pmap_update_lock);

    pmap_update_start = start;
    pmap_update_end = end;
    pmap_nr_updates.count = nr_cpus - 1;
    barrier();
    lapic_ipi_broadcast(TRAP_PMAP_UPDATE);

    /*
     * Perform the local update now so that some time is given to the other
     * processors, which slightly reduces contention on the update counter.
     */
    pmap_kupdate_local(start, end);

    while (pmap_nr_updates.count != 0)
        cpu_pause();

    spinlock_unlock(&pmap_update_lock);
}

void
pmap_update_intr(struct trap_frame *frame)
{
    (void)frame;

    lapic_eoi();

    /* Interrupts are serializing events, no memory barrier required */
    pmap_kupdate_local(pmap_update_start, pmap_update_end);
    atomic_add(&pmap_nr_updates.count, -1);
}

#ifdef X86_PAE
static unsigned long
pmap_pdpt_alloc(size_t slab_size)
{
    struct vm_page *page;
    unsigned long va, start, end;

    va = vm_kmem_alloc_va(slab_size);

    if (va == 0)
        return 0;

    for (start = va, end = va + slab_size; start < end; start += PAGE_SIZE) {
        page = vm_phys_alloc_seg(0, VM_PHYS_SEG_NORMAL);

        if (page == NULL)
            goto error_page;

        pmap_kenter(start, vm_page_to_pa(page));
    }

    pmap_kupdate(va, end);
    return va;

error_page:
    vm_kmem_free(va, slab_size);
    return 0;
}
#endif /* X86_PAE */

void
pmap_setup(void)
{
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

    root_pages = vm_phys_alloc(PMAP_RPTP_ORDER);

    if (root_pages == NULL) {
        error = ERROR_NOMEM;
        goto error_pages;
    }

    pmap->root_pt = vm_page_to_pa(root_pages);

#ifdef X86_PAE
    pmap->pdpt = kmem_cache_alloc(&pmap_pdpt_cache);

    if (pmap->pdpt == NULL) {
        error = ERROR_NOMEM;
        goto error_pdpt;
    }

    va = (unsigned long)pmap->pdpt;
    assert(P2ALIGNED(va, PMAP_PDPT_ALIGN));

    for (i = 0; i < PMAP_NR_RPTPS; i++)
        pmap->pdpt[i] = (pmap->root_pt + (i * PAGE_SIZE)) | PMAP_PTE_P;

    pa = pmap_kextract(va) + (va & PAGE_MASK);
    assert(pa < VM_PHYS_NORMAL_LIMIT);
    pmap->pdpt_pa = (unsigned long)pa;
#endif /* X86_PAE */

    pt_level = &pmap_pt_levels[PMAP_NR_LEVELS - 1];
    kpt = pt_level->ptes;
    index = PMAP_PTEMAP_INDEX(VM_PMAP_PTEMAP_ADDRESS, pt_level->shift);

    pt = (pmap_pte_t *)pmap_map_pt(pmap->root_pt);

    memset(pt, 0, index * sizeof(pmap_pte_t));
    index += PMAP_NR_RPTPS;
    memcpy(&pt[index], &kpt[index], (pt_level->nr_ptes - index)
                                    * sizeof(pmap_pte_t));

    for (i = 0; i < PMAP_NR_RPTPS; i++) {
        va = VM_PMAP_PTEMAP_ADDRESS + (i * (1UL << pt_level->shift));
        index = (va >> pt_level->shift) & ((1UL << pt_level->bits) - 1);
        pa = pmap->root_pt + (i * PAGE_SIZE);
        pt[index] = (pa | PMAP_PTE_RW | PMAP_PTE_P) & pt_level->mask;
    }

    pmap_unmap_pt();

    spinlock_init(&pmap->lock);

    spinlock_lock(&pmap_list_lock);
    list_insert_tail(&pmap_list, &pmap->node);
    spinlock_unlock(&pmap_list_lock);

    *pmapp = pmap;
    return 0;

#ifdef X86_PAE
error_pdpt:
    vm_phys_free(root_pages, PMAP_RPTP_ORDER);
#endif /* X86_PAE */
error_pages:
    kmem_cache_free(&pmap_cache, pmap);
error_pmap:
    return error;
}

void
pmap_load(struct pmap *pmap)
{
    cpu_percpu_set_pmap(pmap);

#ifdef X86_PAE
    cpu_set_cr3(pmap->pdpt_pa);
#else /* X86_PAE */
    cpu_set_cr3(pmap->root_pt);
#endif /* X86_PAE */
}
