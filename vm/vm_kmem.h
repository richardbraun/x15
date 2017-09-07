/*
 * Copyright (c) 2010-2017 Richard Braun
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

#include <stdint.h>

#include <kern/init.h>
#include <machine/pmap.h>
#include <machine/types.h>

/*
 * The kernel space is required not to start at address 0, which is used to
 * report allocation errors.
 */
#if PMAP_START_KMEM_ADDRESS == 0
#error "kernel space must not start at address 0"
#endif /* PMAP_START_KMEM_ADDRESS == 0 */

/*
 * Special kernel addresses.
 */
extern char _text;
extern char _rodata;
extern char _data;
extern char _end;

/*
 * Allocate pure virtual kernel pages.
 *
 * The caller is reponsible for taking care of the underlying physical memory.
 */
void * vm_kmem_alloc_va(size_t size);

/*
 * Free virtual kernel pages.
 *
 * The caller is reponsible for taking care of the underlying physical memory.
 */
void vm_kmem_free_va(void *addr, size_t size);

/*
 * Allocate kernel pages.
 */
void * vm_kmem_alloc(size_t size);

/*
 * Free kernel pages.
 */
void vm_kmem_free(void *addr, size_t size);

/*
 * Map physical memory in the kernel map.
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
void * vm_kmem_map_pa(phys_addr_t pa, size_t size,
                      uintptr_t *map_vap, size_t *map_sizep);

/*
 * Unmap physical memory from the kernel map.
 */
void vm_kmem_unmap_pa(uintptr_t map_va, size_t map_size);

/*
 * This init operation provides :
 *  - kernel virtual memory allocation
 */
INIT_OP_DECLARE(vm_kmem_setup);

#endif /* _VM_VM_KMEM_H */
