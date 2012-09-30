/*
 * Copyright (c) 2010, 2011, 2012 Richard Braun.
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

#ifndef _I386_PMAP_H
#define _I386_PMAP_H

#include <kern/param.h>
#include <kern/types.h>
#include <lib/stdint.h>

/*
 * Page directory/table properties.
 */
#ifdef PAE
#define PMAP_PDE_SHIFT  21
#define PMAP_PT_SHIFT   9
#define PMAP_NR_PDT     4
#define PMAP_PTE_PMASK  0x0000000ffffff000ULL
#else /* PAE */
#define PMAP_PDE_SHIFT  22
#define PMAP_PT_SHIFT   10
#define PMAP_NR_PDT     1
#define PMAP_PTE_PMASK  (~PAGE_MASK)
#endif /* PAE */

#define PMAP_PTE_SHIFT 12

/*
 * The amount of virtual memory described by a page directory/table entry.
 */
#define PMAP_PDE_MAPSIZE    (1 << PMAP_PDE_SHIFT)
#define PMAP_PTE_MAPSIZE    (1 << PMAP_PTE_SHIFT)

/*
 * Number of entries in a page directory/table.
 */
#define PMAP_PTE_PER_PT (1 << PMAP_PT_SHIFT)

/*
 * PDE/PTE flags.
 */
#define PMAP_PTE_PRESENT        0x001
#define PMAP_PTE_WRITE          0x002
#define PMAP_PTE_USER           0x004
#define PMAP_PTE_WRITE_THROUGH  0x008
#define PMAP_PTE_CACHE_DISABLE  0x010
#define PMAP_PTE_ACCESSED       0x020
#define PMAP_PTE_DIRTY          0x040
#define PMAP_PTE_GLOBAL         0x100
#define PMAP_PTE_AVAIL1         0x200
#define PMAP_PTE_AVAIL2         0x400
#define PMAP_PTE_AVAIL3         0x800

/*
 * Flags related to page protection.
 */
#define PMAP_PTE_PROT_MASK PMAP_PTE_WRITE

/*
 * Index of the first PDE for the kernel address space.
 */
#define PMAP_PDE_KERN (VM_MIN_KERNEL_ADDRESS >> PMAP_PDE_SHIFT)

/*
 * PDE index for the page directory.
 */
#define PMAP_PDE_PTE (VM_MAX_KERNEL_ADDRESS >> PMAP_PDE_SHIFT)

/*
 * Page table entry (also usable as a page directory entry or page directory
 * pointer table entry).
 */
#ifdef PAE
typedef uint64_t pmap_pte_t;
#else /* PAE */
typedef uint32_t pmap_pte_t;
#endif /* PAE */

/*
 * Base virtual address of the linear mapping of PTEs.
 */
#define PMAP_PTE_BASE   ((pmap_pte_t *)(PMAP_PDE_PTE << PMAP_PDE_SHIFT))

/*
 * Base virtual address of the page directory, in the linear mapping of PTEs.
 */
#define PMAP_PDP_BASE   (PMAP_PTE_BASE + (PMAP_PDE_PTE * PMAP_PTE_PER_PT))

/*
 * Virtual address of the PDE that points to the PDP.
 */
#define PMAP_PDP_PDE    (PMAP_PDP_BASE + PMAP_PDE_PTE)

/*
 * Number of pages to reserve for the pmap module after the kernel.
 *
 * This pool of pure virtual memory can be used to reserve virtual addresses
 * before the VM system is initialized.
 */
#define PMAP_RESERVED_PAGES 2

/*
 * Physical address map.
 */
struct pmap {
    pmap_pte_t *pdir;   /* Page directory virtual address */
    vm_phys_t pdir_pa;  /* Page directory physical address */
#ifdef PAE
    pmap_pte_t *pdpt;   /* Page directory pointer table physical address */
#endif /* PAE */
};

/*
 * The kernel pmap.
 */
extern struct pmap *kernel_pmap;

/*
 * Kernel page directory.
 */
extern pmap_pte_t pmap_kpdir[PMAP_NR_PDT * PMAP_PTE_PER_PT];

#ifdef PAE
/*
 * Kernel page directory pointer table.
 */
extern pmap_pte_t pmap_kpdpt[PMAP_NR_PDT];
#endif /* PAE */

/*
 * Address below which using the low level kernel pmap functions is safe.
 * Its value is adjusted by calling pmap_growkernel().
 */
extern unsigned long pmap_klimit;

/*
 * Early initialization of the pmap module.
 *
 * When this function is called, basic paging is enabled and the kernel
 * already runs at virtual addresses.
 */
void pmap_bootstrap(void);

/*
 * Allocate pure virtual memory.
 *
 * This memory is obtained from a very small pool of reserved pages located
 * immediately after the kernel. Its purpose is to allow early mappings to
 * be created before the VM system is available.
 */
unsigned long pmap_bootalloc(unsigned int nr_pages);

/*
 * Return the available kernel virtual space in virt_start and virt_end.
 *
 * This function is called early, during initialization of the VM system, and
 * can't be used after since the VM has taken control of the kernel address
 * space.
 */
void pmap_virtual_space(unsigned long *virt_start, unsigned long *virt_end);

/*
 * Preallocate resources so that addresses up to va can be mapped safely in
 * the kernel pmap.
 */
void pmap_growkernel(unsigned long va);

/*
 * Kernel specific mapping functions.
 *
 * Resources for the new mappings must be preallocated.
 */
void pmap_kenter(unsigned long va, vm_phys_t pa);
void pmap_kremove(unsigned long start, unsigned long end);
void pmap_kprotect(unsigned long start, unsigned long end, int prot);
vm_phys_t pmap_kextract(unsigned long va);

/*
 * Zero a page at the given physical address.
 */
void pmap_zero_page(vm_phys_t pa);

#endif /* _I386_PMAP_H */
