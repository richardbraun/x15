/*
 * Copyright (c) 2010, 2011, 2012 Richard Braun
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

#ifndef _VM_VM_KMEM_H
#define _VM_VM_KMEM_H

#include <kern/types.h>

/*
 * Special kernel addresses.
 */
extern char _text;
extern char _rodata;
extern char _data;
extern char _end;

/*
 * The kernel map.
 */
extern struct vm_map *kernel_map;

/*
 * Initialize the vm_kmem module.
 */
void vm_kmem_setup(void);

/*
 * Early kernel memory allocator.
 *
 * The main purpose of this function is to allow the allocation of the
 * physical page table.
 */
unsigned long vm_kmem_bootalloc(size_t size);

/*
 * Return the range of initial virtual memory used by the kernel.
 */
void vm_kmem_boot_space(unsigned long *start, unsigned long *end);

/*
 * Return the page descriptor for the physical page mapped at va in kernel
 * space. The given address must be mapped and valid.
 */
struct vm_page * vm_kmem_lookup_page(unsigned long va);

/*
 * Allocate memory from the kernel map.
 */
unsigned long vm_kmem_alloc(size_t size);

/*
 * Release memory back to the kernel map.
 */
void vm_kmem_free(unsigned long addr, size_t size);

/*
 * Map physical memory in a kernel map.
 *
 * Return the address at which the mapped memory can be accessed. If map_addrp
 * and/or map_sizep aren't NULL, they are updated to the address and size of
 * the mapping created.
 *
 * This is a convenience function for modules that must map random regions of
 * physical memory, and as such, it doesn't expect a page-aligned input range.
 *
 * TODO When mapping attributes are implemented, make this function disable
 * caching on the mapping.
 */
void * vm_kmem_map_pa(phys_addr_t addr, size_t size, unsigned long *map_addrp,
                      size_t *map_sizep);

/*
 * Unmap physical memory from a kernel map.
 */
void vm_kmem_unmap_pa(unsigned long map_addr, size_t map_size);

#endif /* _VM_VM_KMEM_H */
