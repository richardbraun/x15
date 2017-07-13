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
 * Object caching and general purpose memory allocator.
 */

#ifndef _KERN_KMEM_H
#define _KERN_KMEM_H

#include <stddef.h>

#include <kern/init.h>

/*
 * Object cache.
 */
struct kmem_cache;

/*
 * Type for constructor functions.
 *
 * The pre-constructed state of an object is supposed to include only
 * elements such as e.g. linked lists, locks, reference counters. Therefore
 * constructors are expected to 1) never block, 2) never fail and 3) not
 * need any user-provided data. As a result, object construction never
 * performs dynamic resource allocation, which removes the need for
 * destructors.
 */
typedef void (*kmem_ctor_fn_t)(void *);

#include <kern/kmem_i.h>

/*
 * Cache creation flags.
 */
#define KMEM_CACHE_NOOFFSLAB    0x1 /* Don't allocate external slab data */
#define KMEM_CACHE_PAGE_ONLY    0x2 /* Allocate slabs from the page allocator */
#define KMEM_CACHE_VERIFY       0x4 /* Use debugging facilities */

/*
 * Initialize a cache.
 *
 * Slabs may be allocated either from the page allocator or from kernel
 * virtual memory, unless KMEM_CACHE_PAGE_ONLY is set.
 */
void kmem_cache_init(struct kmem_cache *cache, const char *name,
                     size_t obj_size, size_t align, kmem_ctor_fn_t ctor,
                     int flags);

/*
 * Allocate an object from a cache.
 */
void * kmem_cache_alloc(struct kmem_cache *cache);

/*
 * Release an object to its cache.
 */
void kmem_cache_free(struct kmem_cache *cache, void *obj);

/*
 * Display internal cache information.
 *
 * If cache is NULL, this function displays all managed caches.
 */
void kmem_cache_info(struct kmem_cache *cache);

/*
 * Allocate size bytes of uninitialized memory.
 */
void * kmem_alloc(size_t size);

/*
 * Allocate size bytes of zeroed memory.
 */
void * kmem_zalloc(size_t size);

/*
 * Release memory obtained with kmem_alloc() or kmem_zalloc().
 *
 * The size argument must strictly match the value given at allocation time.
 */
void kmem_free(void *ptr, size_t size);

/*
 * Display global kernel memory information.
 */
void kmem_info(void);

/*
 * This init operation provides :
 *  - allocation from caches backed by the page allocator
 */
INIT_OP_DECLARE(kmem_bootstrap);

/*
 * This init operation provides :
 *  - allocation from all caches
 */
INIT_OP_DECLARE(kmem_setup);

#endif /* _KERN_KMEM_H */
