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
 * Early page allocator.
 */

#ifndef _KERN_BOOTMEM_H
#define _KERN_BOOTMEM_H

#include <stdbool.h>
#include <stddef.h>

#include <kern/init.h>
#include <machine/types.h>

/*
 * Helper functions available before paging is enabled.
 *
 * Any memory passed to these must also be accessible without paging.
 */
void * bootmem_memcpy(void *dest, const void *src, size_t n);
void * bootmem_memmove(void *dest, const void *src, size_t n);
void * bootmem_memset(void *s, int c, size_t n);
size_t bootmem_strlen(const char *s);

/*
 * Register a physical memory zone.
 *
 * Zones are expected to be sorted in ascending order of addresses and
 * not overlap. They are later loaded to the VM system. Set direct_mapped
 * to true if the zone is part of the direct mapping of physical memory.
 *
 * This function is called before paging is enabled.
 */
void bootmem_register_zone(unsigned int zone_index, bool direct_mapped,
                           phys_addr_t start, phys_addr_t end);

/*
 * Report reserved addresses to the bootmem module.
 *
 * The kernel is automatically reserved.
 *
 * Once all reserved ranges have been registered, the user can initialize the
 * early page allocator.
 *
 * If the range is marked temporary, it will be unregistered once
 * the boot data have been saved/consumed so that their backing
 * pages are loaded into the VM system.
 *
 * This function is called before paging is enabled.
 */
void bootmem_reserve_range(phys_addr_t start, phys_addr_t end, bool temporary);

/*
 * Initialize the early page allocator.
 *
 * This function builds a heap based on the registered zones while carefuling
 * avoiding reserved data.
 *
 * This function is called before paging is enabled.
 */
void bootmem_setup(void);

/*
 * Allocate contiguous physical pages.
 *
 * The pages returned are guaranteed to be part of the direct physical
 * mapping when paging is enabled.
 *
 * This function should only be used to allocate initial page table pages.
 * Those pages are later loaded into the VM system (as reserved pages)
 * which means they can be freed like other regular pages. Users should
 * fix up the type of those pages once the VM system is initialized.
 *
 * This function is called before paging is enabled.
 */
void * bootmem_alloc(size_t size);

phys_addr_t bootmem_directmap_end(void);

#endif /* _KERN_BOOTMEM_H */
