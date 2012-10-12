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

static struct pmap kernel_pmap_store;
struct pmap *kernel_pmap;

unsigned long pmap_klimit;

/*
 * Kernel page directory.
 */
static pmap_pte_t pmap_kpdir[PMAP_NR_PDT * PMAP_PTE_PER_PT]
    __aligned(PAGE_SIZE) __initdata;

#ifdef PAE
/*
 * Kernel page directory pointer table.
 */
static pmap_pte_t pmap_kpdpt[PMAP_NR_PDT] __aligned(32) __initdata;
#endif /* PAE */

/*
 * Reserved pages of virtual memory available for early allocation.
 */
static unsigned long pmap_boot_heap __initdata;

/*
 * Start of the available virtual kernel space, before the VM system is
 * initialized.
 */
static unsigned long pmap_avail_start __initdata;

/*
 * Table used to convert machine-independent protection flags to
 * machine-dependent PTE bits.
 */
static pmap_pte_t pmap_prot_conv_table[8];

/*
 * This variable is set to PMAP_PTE_GLOBAL if global pages are available.
 */
static pmap_pte_t pmap_pte_global;

/*
 * Address for temporary mappings of pages to zero.
 */
static unsigned long pmap_zero_va;

pmap_pte_t * __init
pmap_setup_paging(void)
{
    pmap_pte_t *pdir, *ptps, *pte, *id_pte;
    unsigned long i, nr_pages, nr_ptps, kern_start, kern_end;

    /*
     * TODO Update comment.
     *
     * Create the kernel virtual mapping. Two mappings are actually established,
     * using the same PTPs: a direct physical mapping, where virtual and
     * physical addresses are identical (the identity mapping), and the true
     * kernel mapping at KERNEL_OFFSET. The identity mapping is required to
     * avoid a fault directly after paging is enabled. In addition, a few pages
     * are reserved immediately after the kernel for the pmap module.
     *
     * While only the kernel is mapped, the PTPs are initialized so that all
     * memory from KERNEL_OFFSET up to the pmap reserved pages can be mapped,
     * which is required by pmap_growkernel().
     */

    /* Allocate the PTPs */
    kern_end = BOOT_VTOP(&_end);
    nr_pages = (kern_end / PAGE_SIZE) + PMAP_RESERVED_PAGES;
    nr_ptps = P2ROUND(nr_pages, PMAP_PTE_PER_PT) / PMAP_PTE_PER_PT;
    ptps = biosmem_bootalloc(nr_ptps);

    /* Insert the PTPs in the page directory */
    pdir = (pmap_pte_t *)pmap_kpdir;
    pte = pdir + (KERNEL_OFFSET >> PMAP_PDE_SHIFT);
    id_pte = pdir;

    for (i = 0; i < nr_ptps; i++) {
        *pte = ((unsigned long)ptps + (i * PAGE_SIZE))
               | PMAP_PTE_WRITE | PMAP_PTE_PRESENT;
        *id_pte++ = *pte++;
    }

    /* Map the kernel */
    kern_start = (unsigned long)&_init;

    for (i = kern_start; i < kern_end; i += PAGE_SIZE)
        ptps[vm_page_atop(i)] = i | PMAP_PTE_WRITE | PMAP_PTE_PRESENT;

#ifdef PAE
    pte = (pmap_pte_t *)pmap_kpdpt;

    for (i = 0; i < PMAP_NR_PDT; i++)
        pte[i] = ((unsigned long)pdir + (i * PAGE_SIZE)) | PMAP_PTE_PRESENT;

    cpu_enable_pae();

    return pte;
#else /* PAE */
    return pdir;
#endif /* PAE */
}

pmap_pte_t * __init
pmap_ap_setup_paging(void)
{
#ifdef PAE
    cpu_enable_pae();
    return (pmap_pte_t *)pmap_kpdpt;
#else /* PAE */
    return (pmap_pte_t *)pmap_kpdir;
#endif /* PAE */
}

static void __init
pmap_setup_global_pages(void)
{
    pmap_pte_t *pde, *pde_end, *pte, *pte_end;

    for (pde = PMAP_PDP_BASE, pde_end = pde + (PMAP_NR_PDT * PMAP_PTE_PER_PT);
         pde < pde_end;
         pde++) {
        if (!(*pde & PMAP_PTE_PRESENT))
            continue;

        for (pte = PMAP_PTE_BASE + ((pde - PMAP_PDP_BASE) * PMAP_PTE_PER_PT),
             pte_end = pte + PMAP_PTE_PER_PT;
             pte < pte_end;
             pte++) {
            if (!(*pte & PMAP_PTE_PRESENT))
                continue;

            *pte |= PMAP_PTE_GLOBAL;
        }
    }

    pmap_pte_global = PMAP_PTE_GLOBAL;
    cpu_enable_global_pages();
}

void __init
pmap_bootstrap(void)
{
    unsigned int i;

    /*
     * First, fill the protection conversion table.
     */
    pmap_prot_conv_table[VM_PROT_NONE] = 0;
    pmap_prot_conv_table[VM_PROT_READ] = 0;
    pmap_prot_conv_table[VM_PROT_WRITE] = PMAP_PTE_WRITE;
    pmap_prot_conv_table[VM_PROT_WRITE | VM_PROT_READ] = PMAP_PTE_WRITE;
    pmap_prot_conv_table[VM_PROT_EXECUTE] = 0;
    pmap_prot_conv_table[VM_PROT_EXECUTE | VM_PROT_READ] = 0;
    pmap_prot_conv_table[VM_PROT_EXECUTE | VM_PROT_WRITE] = PMAP_PTE_WRITE;
    pmap_prot_conv_table[VM_PROT_ALL] = PMAP_PTE_WRITE;

    /*
     * Next, take care of the kernel pmap.
     */
    kernel_pmap = &kernel_pmap_store;
    kernel_pmap->pdir = pmap_kpdir;
    kernel_pmap->pdir_pa = (unsigned long)pmap_kpdir;

#ifdef PAE
    kernel_pmap->pdpt = pmap_kpdpt;
#endif /* PAE */

    /*
     * Establish the linear mapping of PTEs.
     */
    for (i = 0; i < PMAP_NR_PDT; i++)
        kernel_pmap->pdir[PMAP_PDE_PTE + i] =
            ((pmap_pte_t)kernel_pmap->pdir_pa + (i << PMAP_PTE_SHIFT))
            | PMAP_PTE_WRITE | PMAP_PTE_PRESENT;

    cpu_tlb_flush();

    /*
     * Tune section permissions.
     */
    pmap_kprotect((unsigned long)&_text, (unsigned long)&_rodata,
                  VM_PROT_READ | VM_PROT_EXECUTE);
    pmap_kprotect((unsigned long)&_rodata, (unsigned long)&_data, VM_PROT_READ);
    cpu_tlb_flush();

    if (cpu_has_global_pages())
        pmap_setup_global_pages();

    pmap_boot_heap = (unsigned long)&_end;
    pmap_avail_start = pmap_boot_heap + (PMAP_RESERVED_PAGES * PAGE_SIZE);
    pmap_klimit = P2ROUND(pmap_avail_start, PMAP_PDE_MAPSIZE);
    pmap_zero_va = pmap_bootalloc(1);
}

unsigned long __init
pmap_bootalloc(unsigned int nr_pages)
{
    unsigned long page;
    size_t size;

    assert(nr_pages > 0);

    size = nr_pages * PAGE_SIZE;

    assert((pmap_boot_heap + size) > pmap_boot_heap);
    assert((pmap_boot_heap + size) <= pmap_avail_start);

    page = pmap_boot_heap;
    pmap_boot_heap += size;
    return page;
}

static inline pmap_pte_t *
pmap_pde(pmap_pte_t *pdir, unsigned long va)
{
    return &pdir[va >> PMAP_PDE_SHIFT];
}

void __init
pmap_virtual_space(unsigned long *virt_start, unsigned long *virt_end)
{
    *virt_start = pmap_avail_start;
    *virt_end = VM_MAX_KERNEL_ADDRESS;
}

void
pmap_growkernel(unsigned long va)
{
    struct vm_page *page;
    pmap_pte_t *pde;
    phys_addr_t pa;

    while (va > pmap_klimit) {
        pde = pmap_pde(pmap_kpdir, pmap_klimit);
        assert(*pde == 0);

        if (!vm_phys_ready)
            pa = vm_phys_bootalloc();
        else {
            page = vm_phys_alloc(0);

            if (page == NULL)
                panic("pmap: no page available to grow kernel space");

            pa = vm_page_to_pa(page);
        }

        pmap_zero_page(pa);
        *pde = pa | pmap_pte_global | PMAP_PTE_WRITE | PMAP_PTE_PRESENT;
        pmap_klimit = P2ROUND(pmap_klimit + PMAP_PDE_MAPSIZE, PMAP_PDE_MAPSIZE);
    }
}

void
pmap_kenter(unsigned long va, phys_addr_t pa)
{
    PMAP_PTE_BASE[vm_page_atop(va)] = (pa & PMAP_PTE_PMASK) | pmap_pte_global
                                      | PMAP_PTE_WRITE | PMAP_PTE_PRESENT;
    cpu_tlb_flush_va(va);
}

void
pmap_kremove(unsigned long start, unsigned long end)
{
    while (start < end) {
        PMAP_PTE_BASE[vm_page_atop(start)] = 0;
        cpu_tlb_flush_va(start);
        start += PAGE_SIZE;
    }
}

void
pmap_kprotect(unsigned long start, unsigned long end, int prot)
{
    pmap_pte_t *pte, flags;

    flags = pmap_prot_conv_table[prot & VM_PROT_ALL];

    while (start < end) {
        pte = PMAP_PTE_BASE + vm_page_atop(start);
        *pte = (*pte & ~PMAP_PTE_PROT_MASK) | flags;
        cpu_tlb_flush_va(start);
        start += PAGE_SIZE;
    }
}

phys_addr_t
pmap_kextract(unsigned long va)
{
    pmap_pte_t *pde;

    pde = pmap_pde(pmap_kpdir, va);

    if (*pde == 0)
        return 0;

    return PMAP_PTE_BASE[vm_page_atop(va)] & PMAP_PTE_PMASK;
}

void
pmap_zero_page(phys_addr_t pa)
{
    pmap_kenter(pmap_zero_va, pa);
    memset((void *)pmap_zero_va, 0, PAGE_SIZE);
    pmap_kremove(pmap_zero_va, pmap_zero_va + PAGE_SIZE);
}
