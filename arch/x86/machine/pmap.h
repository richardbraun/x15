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
 * TODO Comment.
 */

#ifndef _X86_PMAP_H
#define _X86_PMAP_H

#include <kern/macros.h>

/*
 * Page table entry flags.
 */
#define PMAP_PTE_P      0x00000001
#define PMAP_PTE_RW     0x00000002
#define PMAP_PTE_US     0x00000004
#define PMAP_PTE_PWT    0x00000008
#define PMAP_PTE_PCD    0x00000010
#define PMAP_PTE_A      0x00000020
#define PMAP_PTE_D      0x00000040
#define PMAP_PTE_PS     0x00000080
#define PMAP_PTE_G      0x00000100

/*
 * Page translation hierarchy properties.
 */

/*
 * Masks define valid bits at each page translation level.
 *
 * Additional bits such as the global bit can be added at runtime for optional
 * features.
 */
#define PMAP_L0_MASK    (PMAP_PA_MASK | PMAP_PTE_D | PMAP_PTE_A \
                         | PMAP_PTE_PCD | PMAP_PTE_PWT | PMAP_PTE_US \
                         | PMAP_PTE_RW | PMAP_PTE_P)
#define PMAP_L1_MASK    (PMAP_PA_MASK | PMAP_PTE_A | PMAP_PTE_PCD \
                         | PMAP_PTE_PWT | PMAP_PTE_US | PMAP_PTE_RW \
                         | PMAP_PTE_P)

#ifdef __LP64__
#define PMAP_RPTP_ORDER 0
#define PMAP_NR_LEVELS  4
#define PMAP_L0_BITS    9
#define PMAP_L1_BITS    9
#define PMAP_L2_BITS    9
#define PMAP_L3_BITS    9
#define PMAP_VA_MASK    DECL_CONST(0x0000ffffffffffff, UL)
#define PMAP_PA_MASK    DECL_CONST(0x000ffffffffff000, UL)
#define PMAP_L2_MASK    PMAP_L1_MASK
#define PMAP_L3_MASK    PMAP_L1_MASK
#else /* __LP64__ */
#ifdef X86_PAE
#define PMAP_RPTP_ORDER 2   /* Assume two levels with a 4-page root table */
#define PMAP_NR_LEVELS  2
#define PMAP_L0_BITS    9
#define PMAP_L1_BITS    11
#define PMAP_VA_MASK    DECL_CONST(0xffffffff, UL)
#define PMAP_PA_MASK    DECL_CONST(0x000ffffffffff000, ULL)
#else /* X86_PAE */
#define PMAP_RPTP_ORDER 0
#define PMAP_NR_LEVELS  2
#define PMAP_L0_BITS    10
#define PMAP_L1_BITS    10
#define PMAP_VA_MASK    DECL_CONST(0xffffffff, UL)
#define PMAP_PA_MASK    DECL_CONST(0xfffff000, UL)
#endif /* X86_PAE */
#endif /* __LP64__ */

#define PMAP_L0_SHIFT   12
#define PMAP_L1_SHIFT   (PMAP_L0_SHIFT + PMAP_L0_BITS)
#define PMAP_L2_SHIFT   (PMAP_L1_SHIFT + PMAP_L1_BITS)
#define PMAP_L3_SHIFT   (PMAP_L2_SHIFT + PMAP_L2_BITS)

#define PMAP_L0_PTES_PER_PTP    (1 << PMAP_L0_BITS)
#define PMAP_L1_PTES_PER_PTP    (1 << PMAP_L1_BITS)
#define PMAP_L2_PTES_PER_PTP    (1 << PMAP_L2_BITS)
#define PMAP_L3_PTES_PER_PTP    (1 << PMAP_L3_BITS)

#define PMAP_NR_RPTPS   (1 << PMAP_RPTP_ORDER)

#ifndef __ASSEMBLER__

#include <kern/cpumap.h>
#include <kern/list.h>
#include <kern/mutex.h>
#include <kern/stdint.h>
#include <kern/thread.h>
#include <kern/types.h>
#include <machine/cpu.h>
#include <machine/trap.h>

/*
 * Mapping creation flags.
 */
#define PMAP_PEF_GLOBAL 0x1 /* Create a mapping on all processors */

#ifdef X86_PAE
typedef uint64_t pmap_pte_t;
#else /* X86_PAE */
typedef unsigned long pmap_pte_t;
#endif /* X86_PAE */

/*
 * Physical address map.
 */
struct pmap;

/*
 * The kernel pmap.
 */
extern struct pmap *kernel_pmap;

/*
 * Per physical page data specific to the pmap module.
 *
 * On this architecture, the number of page table entries is stored in page
 * table page descriptors.
 */
struct pmap_page {
    unsigned short nr_ptes;
};

#define PMAP_DEFINE_PAGE

/*
 * Early initialization of the MMU.
 *
 * This function is called before paging is enabled by the boot module. It
 * maps the kernel at physical and virtual addresses, after which all kernel
 * functions and data can be accessed.
 */
pmap_pte_t * pmap_setup_paging(void);

/*
 * This function is called by the AP bootstrap code before paging is enabled.
 */
pmap_pte_t * pmap_ap_setup_paging(void);

/*
 * Early initialization of the pmap module.
 */
void pmap_bootstrap(void);

/*
 * Early initialization of the MMU on APs.
 */
void pmap_ap_bootstrap(void);

/*
 * Allocate pure virtual memory.
 *
 * This memory is obtained from a very small pool of reserved pages located
 * immediately after the kernel. Its purpose is to allow early mappings to
 * be created before the VM system is available.
 */
unsigned long pmap_bootalloc(unsigned int nr_pages);

/*
 * Set up the pmap module.
 *
 * This function should only be called by the VM system, once kernel
 * allocations can be performed safely.
 */
void pmap_setup(void);

/*
 * Set up the pmap module for multiprocessor operations.
 *
 * This function copies the current page tables so that each processor has
 * its own set of page tables. As a result, it must be called right before
 * starting APs to make sure all processors have the same mappings.
 *
 * This function must be called before starting the scheduler whatever the
 * number of processors.
 */
void pmap_mp_setup(void);

/*
 * Initialize pmap thread-specific data for the given thread.
 */
int pmap_thread_init(struct thread *thread);

/*
 * Create a pmap for a user task.
 */
int pmap_create(struct pmap **pmapp);

/*
 * Create a mapping on a physical map.
 *
 * If protection is VM_PROT_NONE, this function behaves as if it were
 * VM_PROT_READ. There must not be an existing valid mapping for the given
 * virtual address.
 *
 * If the mapping is local, it is the responsibility of the caller to take
 * care of migration.
 */
void pmap_enter(struct pmap *pmap, unsigned long va, phys_addr_t pa,
                int prot, int flags);

/*
 * Remove a mapping from a physical map.
 */
void pmap_remove(struct pmap *pmap, unsigned long va,
                 const struct cpumap *cpumap);

/*
 * Set the protection of a mapping in a physical map.
 */
void pmap_protect(struct pmap *pmap, unsigned long va, int prot,
                  const struct cpumap *cpumap);

/*
 * Extract a mapping from a physical map.
 *
 * This function walks the page tables to retrieve the physical address
 * mapped at the given virtual address. If there is no mapping for the
 * virtual address, 0 is returned (implying that page 0 is always reserved).
 */
phys_addr_t pmap_extract(struct pmap *pmap, unsigned long va);

/*
 * Force application of pending modifications on a physical map.
 *
 * The functions that may defer physical map modifications are :
 *  - pmap_enter
 *  - pmap_remove
 *  - pmap_protect
 *
 * On return, all operations previously performed by the calling thread are
 * guaranteed to be applied on their respective processors.
 *
 * Note that pmap_update() doesn't guarantee that modifications performed
 * by different threads are applied.
 *
 * Implies a full memory barrier.
 */
void pmap_update(struct pmap *pmap);

/*
 * Load the given pmap on the current processor.
 *
 * This function must be called with interrupts and preemption disabled.
 */
void pmap_load(struct pmap *pmap);

/*
 * Return the pmap currently loaded on the processor.
 *
 * Since threads may borrow pmaps, this can be different than the pmap
 * of the caller.
 */
static inline struct pmap *
pmap_current(void)
{
    return cpu_percpu_get_pmap();
}

#endif /* __ASSEMBLER__ */

#endif /* _X86_PMAP_H */
