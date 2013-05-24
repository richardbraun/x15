/*
 * Copyright (c) 2010, 2011, 2012, 2013 Richard Braun.
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
 * This file is a top header in the inclusion hierarchy, and shouldn't include
 * other headers that may cause circular dependencies.
 */

#ifndef _X86_PARAM_H
#define _X86_PARAM_H

#include <kern/macros.h>

#define __LITTLE_ENDIAN__

/*
 * L1 cache line size.
 *
 * XXX Use this value until processor selection is available.
 */
#define CPU_L1_SIZE 64

/*
 * Code/data alignment.
 */
#define TEXT_ALIGN  16

#ifdef __LP64__
#define DATA_ALIGN  8
#else /* __LP64__ */
#define DATA_ALIGN  4
#endif /* __LP64__ */

/*
 * System timer frequency.
 *
 * The selected value of 200 translates to a period of 5ms, small enough to
 * provide low latency, and is practical as both a dividend and divisor.
 */
#define HZ 200

/*
 * 4 KiB pages.
 */
#define PAGE_SHIFT  12
#define PAGE_SIZE   (1 << PAGE_SHIFT)
#define PAGE_MASK   (PAGE_SIZE - 1)

/*
 * Kernel stack size for threads and interrupt handlers.
 */
#define STACK_SIZE PAGE_SIZE

/*
 * Virtual memory properties.
 */

/*
 * User space boundaries.
 */
#define VM_MIN_ADDRESS  DECL_CONST(0, UL)

#ifdef __LP64__
#define VM_MAX_ADDRESS  DECL_CONST(0x800000000000, UL)
#else /* __LP64__ */
#define VM_MAX_ADDRESS  DECL_CONST(0xc0000000, UL)
#endif/* __LP64__ */

/*
 * Size of the recursive mapping of PTEs.
 *
 * See the pmap module for more information.
 */
#ifdef __LP64__
#define VM_PMAP_PTEMAP_SIZE DECL_CONST(0x8000000000, UL)
#else /* __LP64__ */
#ifdef X86_PAE
#define VM_PMAP_PTEMAP_SIZE DECL_CONST(0x800000, UL)
#else /* X86_PAE */
#define VM_PMAP_PTEMAP_SIZE DECL_CONST(0x400000, UL)
#endif /* X86_PAE */
#endif /* __LP64__ */

/*
 * Location of the recursive mapping of PTEs.
 *
 * See the pmap module for more information.
 */
#ifdef __LP64__
#define VM_PMAP_PTEMAP_ADDRESS  DECL_CONST(0xffff800000000000, UL)
#else /* __LP64__ */
#define VM_PMAP_PTEMAP_ADDRESS  VM_MAX_ADDRESS
#endif /* __LP64__ */

/*
 * Kernel space boundaries.
 */
#define VM_MIN_KERNEL_ADDRESS   (VM_PMAP_PTEMAP_ADDRESS + VM_PMAP_PTEMAP_SIZE)

/*
 * In addition to being the end of the kernel address space, this is also
 * where the kernel image is loaded. Excluding the kernel image from its
 * address space simplifies bootstrapping, and also saves a static VM map
 * entry.
 */
#ifdef __LP64__
#define VM_MAX_KERNEL_ADDRESS   DECL_CONST(0xffffffff80000000, UL)
#else /* __LP64__ */
#define VM_MAX_KERNEL_ADDRESS   DECL_CONST(0xfc000000, UL)
#endif /* __LP64__ */

/*
 * Virtual space reserved for kernel map entries.
 */
#define VM_MAP_KENTRY_SIZE DECL_CONST(0x800000, UL)

/*
 * Physical memory properties.
 */

#ifdef __LP64__
#define VM_MAX_PHYS_SEG 2
#define VM_PHYS_NORMAL_LIMIT    DECL_CONST(0x100000000, UL)
#define VM_PHYS_HIGHMEM_LIMIT   DECL_CONST(0x10000000000000, UL)
#else /* __LP64__ */
#ifdef X86_PAE
#define VM_MAX_PHYS_SEG 2
#define VM_PHYS_NORMAL_LIMIT    DECL_CONST(0x100000000, ULL)
#define VM_PHYS_HIGHMEM_LIMIT   DECL_CONST(0x10000000000000, ULL)
#else /* X86_PAE */
#define VM_MAX_PHYS_SEG 1
#define VM_PHYS_NORMAL_LIMIT    DECL_CONST(0xfffff000, UL)
#endif /* X86_PAE */
#endif /* __LP64__ */

/*
 * Physical segment indexes.
 */
#define VM_PHYS_SEG_NORMAL      0
#define VM_PHYS_SEG_HIGHMEM     1

/*
 * Number of physical segment lists.
 */
#define VM_NR_PHYS_SEGLIST VM_MAX_PHYS_SEG

/*
 * Segment list priorities.
 */
#define VM_PHYS_SEGLIST_NORMAL  0
#define VM_PHYS_SEGLIST_HIGHMEM 1

#endif /* _X86_PARAM_H */
