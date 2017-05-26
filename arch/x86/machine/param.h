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
 * This file is a top header in the inclusion hierarchy, and shouldn't include
 * other headers that may cause circular dependencies.
 */

#ifndef _X86_PARAM_H
#define _X86_PARAM_H

#include <kern/macros.h>

#ifndef __LITTLE_ENDIAN__
#define __LITTLE_ENDIAN__
#endif /* __LITTLE_ENDIAN__ */

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
 * Attributes for variables that are mostly read and seldom changed.
 */
#define __read_mostly __section(".data.read_mostly")

/*
 * Provide architecture-specific string functions.
 */
#define ARCH_STRING_MEMCPY
#define ARCH_STRING_MEMMOVE
#define ARCH_STRING_MEMSET
#define ARCH_STRING_MEMCMP
#define ARCH_STRING_STRLEN
#define ARCH_STRING_STRCPY
#define ARCH_STRING_STRCMP

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
 * Maximum number of available interrupts.
 */
#define INTR_TABLE_SIZE 256

/*
 * Virtual memory properties.
 */

/*
 * User space boundaries.
 */
#define VM_MIN_ADDRESS              DECL_CONST(0, UL)

#ifdef __LP64__
#define VM_MAX_ADDRESS              DECL_CONST(0x800000000000, UL)
#else /* __LP64__ */
#define VM_MAX_ADDRESS              DECL_CONST(0xc0000000, UL)
#endif/* __LP64__ */

/*
 * Kernel space boundaries.
 */
#ifdef __LP64__
#define VM_MIN_KERNEL_ADDRESS       DECL_CONST(0xffff800000000000, UL)
#define VM_MAX_KERNEL_ADDRESS       DECL_CONST(0xfffffffffffff000, UL)
#else /* __LP64__ */
#define VM_MIN_KERNEL_ADDRESS       VM_MAX_ADDRESS
#define VM_MAX_KERNEL_ADDRESS       DECL_CONST(0xfffff000, UL)
#endif /* __LP64__ */

/*
 * Direct physical mapping boundaries.
 */
#ifdef __LP64__
#define VM_MIN_DIRECTMAP_ADDRESS    VM_MIN_KERNEL_ADDRESS
#define VM_MAX_DIRECTMAP_ADDRESS    DECL_CONST(0xffffc00000000000, UL)
#else /* __LP64__ */
#define VM_MIN_DIRECTMAP_ADDRESS    VM_MAX_ADDRESS
#define VM_MAX_DIRECTMAP_ADDRESS    DECL_CONST(0xf8000000, UL)
#endif /* __LP64__ */

/*
 * Kernel mapping offset.
 *
 * On 32-bits systems, the kernel is linked at addresses included in the
 * direct physical mapping, whereas on 64-bits systems, it is linked at
 * -2 GiB because the "kernel" memory model is used when compiling (see
 * the -mcmodel=kernel gcc option).
 */
#ifdef __LP64__
#define VM_KERNEL_OFFSET            DECL_CONST(0xffffffff80000000, UL)
#else /* __LP64__ */
#define VM_KERNEL_OFFSET            VM_MIN_DIRECTMAP_ADDRESS
#endif /* __LP64__ */

/*
 * Kernel virtual space boundaries.
 *
 * In addition to the direct physical mapping, the kernel has its own virtual
 * memory space.
 */
#define VM_MIN_KMEM_ADDRESS         VM_MAX_DIRECTMAP_ADDRESS

#ifdef __LP64__
#define VM_MAX_KMEM_ADDRESS         VM_KERNEL_OFFSET
#else /* __LP64__ */
#define VM_MAX_KMEM_ADDRESS         VM_MAX_KERNEL_ADDRESS
#endif /* __LP64__ */

/*
 * Physical memory properties.
 */

#define VM_PAGE_DMA_LIMIT       DECL_CONST(0x1000000, UL)

#ifdef __LP64__
#define VM_PAGE_MAX_ZONES       4
#define VM_PAGE_DMA32_LIMIT     DECL_CONST(0x100000000, UL)
#define VM_PAGE_DIRECTMAP_LIMIT DECL_CONST(0x400000000000, UL)
#define VM_PAGE_HIGHMEM_LIMIT   DECL_CONST(0x10000000000000, UL)
#else /* __LP64__ */
#define VM_PAGE_DIRECTMAP_LIMIT DECL_CONST(0x38000000, ULL)
#ifdef X15_X86_PAE
#define VM_PAGE_MAX_ZONES       3
#define VM_PAGE_HIGHMEM_LIMIT   DECL_CONST(0x10000000000000, ULL)
#else /* X15_X86_PAE */
#define VM_PAGE_MAX_ZONES       3
#define VM_PAGE_HIGHMEM_LIMIT   DECL_CONST(0xfffff000, UL)
#endif /* X15_X86_PAE */
#endif /* __LP64__ */

/*
 * Physical zone indexes.
 */
#define VM_PAGE_ZONE_DMA        0

#ifdef __LP64__
#define VM_PAGE_ZONE_DMA32      1
#define VM_PAGE_ZONE_DIRECTMAP  2
#define VM_PAGE_ZONE_HIGHMEM    3
#else /* __LP64__ */
#define VM_PAGE_ZONE_DMA32      1   /* Alias for the DIRECTMAP zone */
#define VM_PAGE_ZONE_DIRECTMAP  1
#define VM_PAGE_ZONE_HIGHMEM    2
#endif /* __LP64__ */

#endif /* _X86_PARAM_H */
