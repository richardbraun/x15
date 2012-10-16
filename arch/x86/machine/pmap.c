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

#include <kern/init.h>
#include <kern/panic.h>
#include <kern/param.h>
#include <kern/types.h>
#include <lib/assert.h>
#include <lib/macros.h>
#include <lib/stddef.h>
#include <lib/string.h>
#include <machine/biosmem.h>
#include <machine/boot.h>
#include <machine/cpu.h>
#include <machine/pmap.h>
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
 */
#define PMAP_RESERVED_PAGES 2

/*
 * Properties of a page translation level.
 */
struct pmap_pt_level {
    unsigned int bits;
    unsigned int shift;
    pmap_pte_t *ptes;   /* PTEs in the recursive mapping */
    pmap_pte_t mask;
};

static struct pmap kernel_pmap_store;
struct pmap *kernel_pmap = &kernel_pmap_store;

unsigned long pmap_klimit;

#ifdef X86_PAE
/*
 * "Hidden" root page table for PAE mode.
 */
static pmap_pte_t pmap_boot_pdpt[PMAP_NR_RPTPS] __aligned(32) __initdata;
static pmap_pte_t pmap_pdpt[PMAP_NR_RPTPS] __aligned(32);
#endif /* X86_PAE */

/*
 * Physical address of the page table root, used during bootstrap.
 */
static pmap_pte_t *pmap_boot_root_pt __initdata;

/*
 * Table of page translation properties.
 *
 * This table is only used before paging is enabled.
 */
static struct pmap_pt_level pmap_boot_pt_levels[] __initdata = {
    { PMAP_L1_BITS, PMAP_L1_SHIFT, PMAP_PTEMAP_BASE, PMAP_L1_MASK },
    { PMAP_L2_BITS, PMAP_L2_SHIFT, PMAP_L2_PTEMAP, PMAP_L2_MASK },
#if PMAP_NR_LEVELS > 2
    { PMAP_L3_BITS, PMAP_L3_SHIFT, PMAP_L3_PTEMAP, PMAP_L3_MASK },
#if PMAP_NR_LEVELS > 3
    { PMAP_L4_BITS, PMAP_L4_SHIFT, PMAP_L4_PTEMAP, PMAP_L4_MASK }
#endif /* PMAP_NR_LEVELS > 3 */
#endif /* PMAP_NR_LEVELS > 2 */
};

/*
 * Reserved pages of virtual memory available for early allocation.
 */
static unsigned long pmap_boot_heap __initdata;
static unsigned long pmap_boot_heap_end __initdata;

/*
 * Table of page translation properties.
 *
 * Located at high virtual addresses, it is filled during initialization from
 * the content of its bootstrap version.
 */
static struct pmap_pt_level pmap_pt_levels[ARRAY_SIZE(pmap_boot_pt_levels)];

/*
 * Table used to convert machine-independent protection flags to
 * machine-dependent PTE bits.
 */
static pmap_pte_t pmap_prot_table[8];

/*
 * Special addresses for temporary mappings.
 */
static unsigned long pmap_zero_va;

/*
 * This variable is set to PMAP_PTE_G if global pages are available.
 */
static pmap_pte_t pmap_pte_global;

static void __init
pmap_boot_enter(pmap_pte_t *root_pt, unsigned long va, phys_addr_t pa)
{
    const struct pmap_pt_level *pt_level;
    unsigned int level, index;
    pmap_pte_t *pt, *ptp, *pte;

    if (pa != (pa & PMAP_PA_MASK))
        boot_panic("pmap: invalid physical address");

    pt = root_pt;

    for (level = PMAP_NR_LEVELS; level > 1; level--) {
        pt_level = &pmap_boot_pt_levels[level - 1];
        index = (va >> pt_level->shift) & ((1 << pt_level->bits) - 1);
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

    pte = &pt[(va >> PMAP_L1_SHIFT) & ((1 << PMAP_L1_BITS) - 1)];
    *pte = (pa & PMAP_PA_MASK) | PMAP_PTE_RW | PMAP_PTE_P;
}

static void __init
pmap_setup_recursive_mapping(pmap_pte_t *root_pt)
{
    const struct pmap_pt_level *pt_level;
    unsigned long addr;
    unsigned int i, index;

    pt_level = &pmap_boot_pt_levels[PMAP_NR_LEVELS - 1];

    for (i = 0; i < PMAP_NR_RPTPS; i++) {
        addr = VM_PMAP_PTEMAP_ADDRESS + (i * (1 << pt_level->shift));
        index = (addr >> pt_level->shift) & ((1 << pt_level->bits) - 1);
        addr = (unsigned long)root_pt + (i * PAGE_SIZE);
        root_pt[index] = (addr | PMAP_PTE_RW | PMAP_PTE_P) & pt_level->mask;
    }
}

pmap_pte_t * __init
pmap_setup_paging(void)
{
    pmap_pte_t *root_pt;
    unsigned long va;
    phys_addr_t pa;
    size_t i, size;

    /*
     * Create the kernel mappings. The first two are for the .init section and
     * the persistent kernel code and data at high addresses respectively. The
     * .init section mapping also acts as the mandatory identity mapping.
     * The third is the recursive mapping of PTEs.
     *
     * Any page table required for the virtual addresses that are reserved by
     * this module is also allocated.
     */

    root_pt = biosmem_bootalloc(PMAP_NR_RPTPS);

    va = vm_page_trunc((unsigned long)&_init);
    pa = va;
    size = vm_page_round((unsigned long)&_einit) - va;

    for (i = 0; i < size; i += PAGE_SIZE) {
        pmap_boot_enter(root_pt, va, pa);
        va += PAGE_SIZE;
        pa += PAGE_SIZE;
    }

    va = vm_page_trunc((unsigned long)&_text);
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

    pmap_setup_recursive_mapping(root_pt);

#ifdef X86_PAE
    for (i = 0; i < PMAP_NR_RPTPS; i++)
        pmap_boot_pdpt[i] = ((unsigned long)root_pt + (i * PAGE_SIZE))
                            | PMAP_PTE_P;

    pmap_boot_root_pt = pmap_boot_pdpt;
    cpu_enable_pae();
#else /* X86_PAE */
    pmap_boot_root_pt = root_pt;
#endif /* X86_PAE */

    return pmap_boot_root_pt;
}

pmap_pte_t * __init
pmap_ap_setup_paging(void)
{
#ifdef X86_PAE
    cpu_enable_pae();
#endif /* X86_PAE */

    return pmap_boot_root_pt;
}

static pmap_pte_t * __init
pmap_kpte(unsigned long va)
{
    const struct pmap_pt_level *pt_level;
    unsigned int level;
    pmap_pte_t *pte;

    for (level = PMAP_NR_LEVELS; level > 0; level--) {
        pt_level = &pmap_pt_levels[level - 1];
        pte = &pt_level->ptes[PMAP_PTEMAP_INDEX(va, pt_level->shift)];

        if (!(*pte & PMAP_PTE_P))
            return NULL;
    }

    return pte;
}

static void __init
pmap_setup_global_pages(void)
{
    unsigned long va;
    pmap_pte_t *pte;

    for (va = VM_MAX_KERNEL_ADDRESS;
         va >= VM_MAX_KERNEL_ADDRESS;
         va += PAGE_SIZE) {
        pte = pmap_kpte(va);

        if (pte == NULL)
            continue;

        *pte |= PMAP_PTE_G;
    }

    pmap_pt_levels[0].mask |= PMAP_PTE_G;
    pmap_pte_global = PMAP_PTE_G;
    cpu_enable_global_pages();
}

void __init
pmap_bootstrap(void)
{
    memcpy(pmap_pt_levels, pmap_boot_pt_levels, sizeof(pmap_pt_levels));

#ifdef X86_PAE
    memcpy(pmap_pdpt, pmap_boot_pdpt, sizeof(pmap_pdpt));
    pmap_boot_root_pt = (void *)BOOT_VTOP((unsigned long)pmap_pdpt);
    kernel_pmap->root_pt = (unsigned long)pmap_boot_root_pt;
    cpu_set_cr3(kernel_pmap->root_pt);
#else /* X86_PAE */
    kernel_pmap->root_pt = (unsigned long)pmap_boot_root_pt;
#endif /* X86_PAE */

    pmap_prot_table[VM_PROT_NONE] = 0;
    pmap_prot_table[VM_PROT_READ] = 0;
    pmap_prot_table[VM_PROT_WRITE] = PMAP_PTE_RW;
    pmap_prot_table[VM_PROT_WRITE | VM_PROT_READ] = PMAP_PTE_RW;
    pmap_prot_table[VM_PROT_EXECUTE] = 0;
    pmap_prot_table[VM_PROT_EXECUTE | VM_PROT_READ] = 0;
    pmap_prot_table[VM_PROT_EXECUTE | VM_PROT_WRITE] = PMAP_PTE_RW;
    pmap_prot_table[VM_PROT_ALL] = PMAP_PTE_RW;

    pmap_boot_heap = (unsigned long)&_end;
    pmap_boot_heap_end = pmap_boot_heap + (PMAP_RESERVED_PAGES * PAGE_SIZE);
    pmap_zero_va = pmap_bootalloc(1);

    pmap_kprotect((unsigned long)&_text, (unsigned long)&_rodata,
                  VM_PROT_READ | VM_PROT_EXECUTE);
    pmap_kprotect((unsigned long)&_rodata, (unsigned long)&_data, VM_PROT_READ);

    if (cpu_has_global_pages())
        pmap_setup_global_pages();

    cpu_tlb_flush();

    pmap_klimit = VM_MIN_KERNEL_ADDRESS;
}

void __init
pmap_ap_bootstrap(void)
{
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

void
pmap_growkernel(unsigned long va)
{
    const struct pmap_pt_level *pt_level;
    struct vm_page *page;
    unsigned long start;
    unsigned int level, i, i_start, i_va;
    pmap_pte_t *pte;
    phys_addr_t pa;

    start = pmap_klimit;
    va = P2END(va, 1 << PMAP_L2_SHIFT) - 1;
    assert(start < va);

    for (level = PMAP_NR_LEVELS; level > 1; level--) {
        pt_level = &pmap_pt_levels[level - 1];
        i_start = PMAP_PTEMAP_INDEX(start, pt_level->shift);
        i_va = PMAP_PTEMAP_INDEX(va, pt_level->shift);

        for (i = i_start; i <= i_va; i++) {
            pte = &pt_level->ptes[i];

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
                *pte = (pa | pmap_pte_global | PMAP_PTE_RW | PMAP_PTE_P)
                       & pt_level->mask;
            }
        }
    }

    pmap_klimit = va + 1;
}

void
pmap_kenter(unsigned long va, phys_addr_t pa)
{
    pmap_pte_t *pte;

    pte = PMAP_PTEMAP_BASE + PMAP_PTEMAP_INDEX(va, PMAP_L1_SHIFT);
    *pte = ((pa & PMAP_PA_MASK) | pmap_pte_global | PMAP_PTE_RW | PMAP_PTE_P)
           & pmap_pt_levels[0].mask;
    cpu_tlb_flush_va(va);
}

void
pmap_kremove(unsigned long start, unsigned long end)
{
    pmap_pte_t *pte;

    while (start < end) {
        pte = PMAP_PTEMAP_BASE + PMAP_PTEMAP_INDEX(start, PMAP_L1_SHIFT);
        *pte = 0;
        cpu_tlb_flush_va(start);
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
        cpu_tlb_flush_va(start);
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

void
pmap_zero_page(phys_addr_t pa)
{
    pmap_kenter(pmap_zero_va, pa);
    memset((void *)pmap_zero_va, 0, PAGE_SIZE);
    pmap_kremove(pmap_zero_va, pmap_zero_va + PAGE_SIZE);
}
