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
 *
 *
 * Physical page allocator.
 */

#ifndef _VM_VM_PHYS_H
#define _VM_VM_PHYS_H

#include <kern/types.h>
#include <vm/vm_page.h>

/*
 * True if the vm_phys module is completely initialized, false otherwise
 * (in which case only vm_phys_bootalloc() can be used for allocations).
 */
extern int vm_phys_ready;

/*
 * Load physical memory into the vm_phys module at boot time.
 *
 * The avail_start and avail_end parameters are used to maintain a simple
 * heap for bootstrap allocations.
 */
void vm_phys_load(const char *name, phys_addr_t start, phys_addr_t end,
                  phys_addr_t avail_start, phys_addr_t avail_end,
                  unsigned int seg_index, unsigned int seglist_prio);

/*
 * Allocate one physical page.
 *
 * This function is used to allocate physical memory at boot time, before the
 * vm_phys module is ready, but after the physical memory has been loaded.
 */
phys_addr_t vm_phys_bootalloc(void);

/*
 * Set up the vm_phys module.
 *
 * Once this function returns, the vm_phys module is ready, and normal
 * allocation functions can be used.
 */
void vm_phys_setup(void);

/*
 * Make the given page managed by the vm_phys module.
 *
 * If additional memory can be made usable after the VM system is initialized,
 * it should be reported through this function.
 */
void vm_phys_manage(struct vm_page *page);

/*
 * Return the page descriptor for the given physical address.
 */
struct vm_page * vm_phys_lookup_page(phys_addr_t pa);

/*
 * Allocate a block of 2^order physical pages.
 */
struct vm_page * vm_phys_alloc(unsigned int order);

/*
 * Allocate physical pages from a specific segment.
 *
 * This function shouldn't only be called by architecture specific functions.
 */
struct vm_page * vm_phys_alloc_seg(unsigned int order, unsigned int seg_index);

/*
 * Release a block of 2^order physical pages.
 */
void vm_phys_free(struct vm_page *page, unsigned int order);

/*
 * Display internal information about the module.
 */
void vm_phys_info(void);

#endif /* _VM_VM_PHYS_H */
