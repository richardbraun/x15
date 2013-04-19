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
 * Object caching and general purpose memory allocator.
 */

#ifndef _KERN_KMEM_H
#define _KERN_KMEM_H

#include <kern/stddef.h>

/*
 * Object cache.
 */
struct kmem_cache;

/*
 * Type for constructor functions.
 *
 * The pre-constructed state of an object is supposed to include only
 * elements such as e.g. linked lists, locks, reference counters. Therefore
 * constructors are expected to 1) never fail and 2) not need any
 * user-provided data. The first constraint implies that object construction
 * never performs dynamic resource allocation, which also means there is no
 * need for destructors.
 */
typedef void (*kmem_cache_ctor_t)(void *);

/*
 * Types for slab allocation/free functions.
 *
 * All addresses and sizes must be page-aligned.
 */
typedef unsigned long (*kmem_slab_alloc_fn_t)(size_t);
typedef void (*kmem_slab_free_fn_t)(unsigned long, size_t);

#include <kern/kmem_i.h>

/*
 * Cache creation flags.
 */
#define KMEM_CACHE_NOCPUPOOL    0x1 /* Don't use the per-CPU pools */
#define KMEM_CACHE_NOOFFSLAB    0x2 /* Don't allocate external slab data */
#define KMEM_CACHE_VERIFY       0x4 /* Use debugging facilities */

/*
 * Initialize a cache.
 *
 * If a slab allocation/free function pointer is NULL, the default backend
 * (vm_kmem on the kernel map) is used for the allocation/free action.
 */
void kmem_cache_init(struct kmem_cache *cache, const char *name,
                     size_t obj_size, size_t align, kmem_cache_ctor_t ctor,
                     kmem_slab_alloc_fn_t slab_alloc_fn,
                     kmem_slab_free_fn_t slab_free_fn, int flags);

static inline size_t
kmem_cache_slab_size(struct kmem_cache *cache)
{
    return cache->slab_size;
}

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
 * Set up the kernel memory allocator module.
 *
 * This function should only be called by the VM system. Once it returns,
 * caches can be initialized, but those using the default backend can only
 * operate once the VM system is sufficiently ready.
 */
void kmem_setup(void);

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

#endif /* _KERN_KMEM_H */
