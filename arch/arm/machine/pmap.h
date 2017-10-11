/*
 * Copyright (c) 2017 Richard Braun.
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

#ifndef _ARM_PMAP_H
#define _ARM_PMAP_H

#include <kern/macros.h>

/*
 * Virtual memory layout.
 */

/*
 * User space boundaries.
 */
#define PMAP_START_ADDRESS              DECL_CONST(0, UL)
#define PMAP_END_ADDRESS                DECL_CONST(0xc0000000, UL)

/*
 * Kernel space boundaries.
 */
#define PMAP_START_KERNEL_ADDRESS       PMAP_END_ADDRESS
#define PMAP_END_KERNEL_ADDRESS         DECL_CONST(0xfffff000, UL)

/*
 * Direct physical mapping boundaries.
 */
#define PMAP_START_DIRECTMAP_ADDRESS    PMAP_START_KERNEL_ADDRESS
#define PMAP_END_DIRECTMAP_ADDRESS      DECL_CONST(0xf8000000, UL)

/*
 * Kernel mapping offset.
 */
#define PMAP_KERNEL_OFFSET              PMAP_START_DIRECTMAP_ADDRESS

/*
 * Kernel virtual space boundaries.
 *
 * In addition to the direct physical mapping, the kernel has its own virtual
 * memory space.
 */
#define PMAP_START_KMEM_ADDRESS         PMAP_END_DIRECTMAP_ADDRESS
#define PMAP_END_KMEM_ADDRESS           PMAP_END_KERNEL_ADDRESS

/*
 * Page table entry flags.
 */
#define PMAP_PTE_TYPE_COARSE    0x00000001
#define PMAP_PTE_TYPE_SMALL     0x00000002
#define PMAP_PTE_TYPE_SECTION   0x00000002

#define PMAP_PTE_B              0x00000004
#define PMAP_PTE_C              0x00000008

#define PMAP_PTE_L0_RW          0x00000030
#define PMAP_PTE_L1_RW          0x00000c00

/*
 * Page translation hierarchy properties.
 */

#if 0
/*
 * Masks define valid bits at each page translation level.
 *
 * Additional bits such as the global bit can be added at runtime for optional
 * features.
 */
#define PMAP_L0_MASK            (PMAP_PA_MASK | PMAP_PTE_D | PMAP_PTE_A \
                                 | PMAP_PTE_PCD | PMAP_PTE_PWT | PMAP_PTE_US \
                                 | PMAP_PTE_RW | PMAP_PTE_P)
#define PMAP_L1_MASK            (PMAP_PA_MASK | PMAP_PTE_A | PMAP_PTE_PCD \
                                 | PMAP_PTE_PWT | PMAP_PTE_US | PMAP_PTE_RW \
                                 | PMAP_PTE_P)
#endif

#define PMAP_NR_LEVELS          2
#define PMAP_L0_BITS            8
#define PMAP_L1_BITS            12

#define PMAP_VA_MASK            DECL_CONST(0xffffffff, UL)

#define PMAP_PA_L0_MASK         DECL_CONST(0xfffff000, UL)
#define PMAP_PA_L1_MASK         DECL_CONST(0xfffffc00, UL)

#define PMAP_L0_SKIP            12
#define PMAP_L1_SKIP            (PMAP_L0_SKIP + PMAP_L0_BITS)

#define PMAP_L0_PTES_PER_PT     (1 << PMAP_L0_BITS)
#define PMAP_L1_PTES_PER_PT     (1 << PMAP_L1_BITS)

#ifndef __ASSEMBLER__

#include <stdint.h>

#include <kern/cpumap.h>
#include <kern/init.h>
#include <kern/list.h>
#include <kern/mutex.h>
#include <kern/thread.h>
#include <machine/cpu.h>
#include <machine/types.h>

/*
 * Mapping creation flags.
 */
#define PMAP_PEF_GLOBAL 0x1 /* Create a mapping on all processors */

typedef phys_addr_t pmap_pte_t;

/*
 * Physical address map.
 */
struct pmap;

static inline struct pmap *
pmap_get_kernel_pmap(void)
{
    extern struct pmap pmap_kernel_pmap;

    return &pmap_kernel_pmap;
}

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
 * Initialize the pmap module on APs.
 */
void pmap_ap_setup(void);

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
 * Build/clean up pmap thread-local data for the given thread.
 */
int pmap_thread_build(struct thread *thread);
void pmap_thread_cleanup(struct thread *thread);

/*
 * Extract a mapping from the kernel map.
 *
 * This function walks the page tables to retrieve the physical address
 * mapped at the given virtual address.
 */
int pmap_kextract(uintptr_t va, phys_addr_t *pap);

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
 *
 * This function may trigger an implicit update.
 */
int pmap_enter(struct pmap *pmap, uintptr_t va, phys_addr_t pa,
               int prot, int flags);

/*
 * Remove a mapping from a physical map.
 *
 * The caller may use this function on non-existent mappings.
 *
 * This function may trigger an implicit update.
 */
int pmap_remove(struct pmap *pmap, uintptr_t va,
                const struct cpumap *cpumap);

/*
 * Set the protection of a mapping in a physical map.
 *
 * This function may trigger an implicit update.
 */
int pmap_protect(struct pmap *pmap, uintptr_t va, int prot,
                 const struct cpumap *cpumap);

/*
 * Force application of pending modifications on a physical map.
 *
 * The functions that may defer physical map modifications are :
 *  - pmap_enter
 *  - pmap_remove
 *  - pmap_protect
 *
 * On return, if successful, all operations previously performed by the
 * calling thread are guaranteed to be applied on their respective
 * processors. Note that this function doesn't guarantee that modifications
 * performed by different threads are applied.
 *
 * If an error occurs, then some or all of the pending modifications
 * could not be applied. This function lacks the knowledge to handle
 * such cases. As a result, the caller is responsible for the complete
 * set of affected mappings and must take appropriate actions to restore
 * physical mappings consistency. Note that multiple errors may occur
 * when calling this function. The caller shouldn't rely on the specific
 * error value, and should consider the whole operation to have failed.
 *
 * Also note that the only operation that may fail is mapping creation.
 * Therefore, if the caller only queues removals or protection changes
 * between two calls to this function, it is guaranteed to succeed.
 */
int pmap_update(struct pmap *pmap);

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
#if 0
static inline struct pmap *
pmap_current(void)
{
    extern struct pmap *pmap_current_ptr;
    return cpu_local_read(pmap_current_ptr);
}
#endif

/*
 * This init operation provides :
 *  - kernel pmap operations
 */
INIT_OP_DECLARE(pmap_bootstrap);

/*
 * This init operation provides :
 *  - user pmap creation
 *  - module fully initialized
 */
INIT_OP_DECLARE(pmap_setup);

#endif /* __ASSEMBLER__ */

#endif /* _ARM_PMAP_H */
