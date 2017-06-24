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
 * Physical memory layout.
 *
 * This file is a top header in the inclusion hierarchy, and shouldn't include
 * other headers that may cause circular dependencies.
 */

#ifndef _X86_PMEM_H
#define _X86_PMEM_H

#include <kern/macros.h>

/*
 * Zone boundaries.
 */

#define PMEM_DMA_LIMIT          DECL_CONST(0x1000000, UL)

#ifdef __LP64__
#define PMEM_MAX_ZONES          4
#define PMEM_DMA32_LIMIT        DECL_CONST(0x100000000, UL)
#define PMEM_DIRECTMAP_LIMIT    DECL_CONST(0x400000000000, UL)
#define PMEM_HIGHMEM_LIMIT      DECL_CONST(0x10000000000000, UL)
#else /* __LP64__ */
#define PMEM_DIRECTMAP_LIMIT    DECL_CONST(0x38000000, ULL)
#ifdef X15_X86_PAE
#define PMEM_MAX_ZONES          3
#define PMEM_HIGHMEM_LIMIT      DECL_CONST(0x10000000000000, ULL)
#else /* X15_X86_PAE */
#define PMEM_MAX_ZONES          3
#define PMEM_HIGHMEM_LIMIT      DECL_CONST(0xfffff000, UL)
#endif /* X15_X86_PAE */
#endif /* __LP64__ */

/*
 * Zone vm_page indexes.
 */

#define PMEM_ZONE_DMA           0
#define PMEM_ZONE_DMA32         1

#ifdef __LP64__
#define PMEM_ZONE_DIRECTMAP     2
#define PMEM_ZONE_HIGHMEM       3
#else /* __LP64__ */
#define PMEM_ZONE_DMA32         1
#define PMEM_ZONE_DIRECTMAP     1   /* Alias for the DMA32 zone */
#define PMEM_ZONE_HIGHMEM       2
#endif /* __LP64__ */

#endif /* _X86_PMEM_H */
