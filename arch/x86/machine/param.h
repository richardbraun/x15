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

#ifndef _X86_PARAM_H
#define _X86_PARAM_H

#include <machine/boot.h>
#include <lib/macros.h>

#define __LITTLE_ENDIAN__

/*
 * L1 cache line size.
 *
 * XXX Use this value until processor selection is available.
 */
#define CPU_L1_SIZE 64

/*
 * System timer frequency.
 */
#define HZ 100

/*
 * 4 KiB virtual pages.
 */
#define PAGE_SHIFT 12

/*
 * User space boundaries.
 */
#define VM_MIN_ADDRESS  DECL_CONST(0, UL)
#define VM_MAX_ADDRESS  KERNEL_OFFSET

/*
 * Kernel stack size for threads and interrupt handlers.
 */
#define STACK_SIZE 4096

/*
 * Size of a linear mapping of PTEs (see the pmap module).
 */
#ifdef PAE
#define VM_PMAP_PTEMAP_SIZE DECL_CONST(0x800000, UL)
#else /* PAE */
#define VM_PMAP_PTEMAP_SIZE DECL_CONST(0x400000, UL)
#endif /* PAE */

/*
 * Kernel space boundaries.
 *
 * Addresses beyond VM_MAX_KERNEL_ADDRESS are used for PTEs linear mappings.
 * An area the size of such a mapping is reserved to avoid overflows.
 *
 * See the pmap module for more information.
 */
#define VM_MIN_KERNEL_ADDRESS   VM_MAX_ADDRESS
#define VM_MAX_KERNEL_ADDRESS   (~(VM_PMAP_PTEMAP_SIZE * 2) + 1)

/*
 * Maximum number of physical segments.
 */
#ifdef PAE
#define VM_MAX_PHYS_SEG 2
#else /* PAE */
#define VM_MAX_PHYS_SEG 1
#endif /* PAE */

/*
 * Number of physical segment lists.
 */
#define VM_NR_PHYS_SEGLIST VM_MAX_PHYS_SEG

/*
 * Segment list priorities.
 */
#define VM_PHYS_SEGLIST_HIGHMEM 1
#define VM_PHYS_SEGLIST_NORMAL  0

/*
 * Segment boundaries.
 */
#ifdef PAE
#define VM_PHYS_NORMAL_LIMIT    DECL_CONST(0x100000000, ULL)
#define VM_PHYS_HIGHMEM_LIMIT   DECL_CONST(0x1000000000, ULL)
#else /* PAE */
#define VM_PHYS_NORMAL_LIMIT    DECL_CONST(0xfffff000, UL)
#endif /* PAE */

/*
 * Virtual space reserved for kernel map entries.
 */
#define VM_MAP_KENTRY_SIZE DECL_CONST(0x800000, UL)

#endif /* _X86_PARAM_H */
