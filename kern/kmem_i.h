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
 */

#ifndef _KERN_KMEM_I_H
#define _KERN_KMEM_I_H

#include <kern/list.h>
#include <kern/mutex.h>
#include <kern/param.h>
#include <kern/stddef.h>

/*
 * Per-processor cache of pre-constructed objects.
 *
 * The flags member is a read-only CPU-local copy of the parent cache flags.
 */
struct kmem_cpu_pool {
    struct mutex lock;
    int flags;
    int size;
    int transfer_size;
    int nr_objs;
    void **array;
} __aligned(CPU_L1_SIZE);

/*
 * When a cache is created, its CPU pool type is determined from the buffer
 * size. For small buffer sizes, many objects can be cached in a CPU pool.
 * Conversely, for large buffer sizes, this would incur much overhead, so only
 * a few objects are stored in a CPU pool.
 */
struct kmem_cpu_pool_type {
    size_t buf_size;
    int array_size;
    size_t array_align;
    struct kmem_cache *array_cache;
};

/*
 * Buffer descriptor.
 *
 * For normal caches (i.e. without KMEM_CF_VERIFY), bufctls are located at the
 * end of (but inside) each buffer. If KMEM_CF_VERIFY is set, bufctls are
 * located after each buffer.
 *
 * When an object is allocated to a client, its bufctl isn't used. This memory
 * is instead used for redzoning if cache debugging is in effect.
 */
union kmem_bufctl {
    union kmem_bufctl *next;
    unsigned long redzone;
};

/*
 * Redzone guard word.
 */
#ifdef __LP64__
#ifdef __BIG_ENDIAN__
#define KMEM_REDZONE_WORD 0xfeedfacefeedfaceUL
#else /* __BIG_ENDIAN__ */
#define KMEM_REDZONE_WORD 0xcefaedfecefaedfeUL
#endif /* __BIG_ENDIAN__ */
#else /* __LP64__ */
#ifdef __BIG_ENDIAN__
#define KMEM_REDZONE_WORD 0xfeedfaceUL
#else /* __BIG_ENDIAN__ */
#define KMEM_REDZONE_WORD 0xcefaedfeUL
#endif /* __BIG_ENDIAN__ */
#endif /* __LP64__ */

/*
 * Redzone byte for padding.
 */
#define KMEM_REDZONE_BYTE 0xbb

/*
 * Buffer tag.
 *
 * This structure is only used for KMEM_CF_VERIFY caches. It is located after
 * the bufctl and includes information about the state of the buffer it
 * describes (allocated or not). It should be thought of as a debugging
 * extension of the bufctl.
 */
struct kmem_buftag {
    unsigned long state;
};

/*
 * Values the buftag state member can take.
 */
#ifdef __LP64__
#ifdef __BIG_ENDIAN__
#define KMEM_BUFTAG_ALLOC   0xa110c8eda110c8edUL
#define KMEM_BUFTAG_FREE    0xf4eeb10cf4eeb10cUL
#else /* __BIG_ENDIAN__ */
#define KMEM_BUFTAG_ALLOC   0xedc810a1edc810a1UL
#define KMEM_BUFTAG_FREE    0x0cb1eef40cb1eef4UL
#endif /* __BIG_ENDIAN__ */
#else /* __LP64__ */
#ifdef __BIG_ENDIAN__
#define KMEM_BUFTAG_ALLOC   0xa110c8edUL
#define KMEM_BUFTAG_FREE    0xf4eeb10cUL
#else /* __BIG_ENDIAN__ */
#define KMEM_BUFTAG_ALLOC   0xedc810a1UL
#define KMEM_BUFTAG_FREE    0x0cb1eef4UL
#endif /* __BIG_ENDIAN__ */
#endif /* __LP64__ */

/*
 * Free and uninitialized patterns.
 *
 * These values are unconditionnally 64-bit wide since buffers are at least
 * 8-byte aligned.
 */
#ifdef __BIG_ENDIAN__
#define KMEM_FREE_PATTERN   0xdeadbeefdeadbeefULL
#define KMEM_UNINIT_PATTERN 0xbaddcafebaddcafeULL
#else /* __BIG_ENDIAN__ */
#define KMEM_FREE_PATTERN   0xefbeaddeefbeaddeULL
#define KMEM_UNINIT_PATTERN 0xfecaddbafecaddbaULL
#endif /* __BIG_ENDIAN__ */

/*
 * Page-aligned collection of unconstructed buffers.
 *
 * This structure is either allocated from the slab cache, or, when internal
 * fragmentation allows it, or if forced by the cache creator, from the slab
 * it describes.
 */
struct kmem_slab {
    struct list node;
    unsigned long nr_refs;
    union kmem_bufctl *first_free;
    void *addr;
};

/*
 * Cache name buffer size.
 */
#define KMEM_NAME_SIZE 32

/*
 * Cache flags.
 *
 * The flags don't change once set and can be tested without locking.
 */
#define KMEM_CF_NO_CPU_POOL     0x1 /* CPU pool layer disabled */
#define KMEM_CF_SLAB_EXTERNAL   0x2 /* Slab data is off slab */
#define KMEM_CF_VERIFY          0x4 /* Debugging facilities enabled */
#define KMEM_CF_DIRECT          0x8 /* Quick buf-to-slab lookup */

/*
 * Cache of objects.
 *
 * Locking order : cpu_pool -> cache. CPU pools locking is ordered by CPU ID.
 */
struct kmem_cache {
    /* CPU pool layer */
    struct kmem_cpu_pool cpu_pools[MAX_CPUS];
    struct kmem_cpu_pool_type *cpu_pool_type;

    /* Slab layer */
    struct mutex lock;
    struct list node;   /* Cache list linkage */
    struct list partial_slabs;
    struct list free_slabs;
    int flags;
    size_t obj_size;    /* User-provided size */
    size_t align;
    size_t buf_size;    /* Aligned object size */
    size_t bufctl_dist; /* Distance from buffer to bufctl */
    size_t slab_size;
    size_t color;
    size_t color_max;
    unsigned long bufs_per_slab;
    unsigned long nr_objs;  /* Number of allocated objects */
    unsigned long nr_bufs;  /* Total number of buffers */
    unsigned long nr_slabs;
    unsigned long nr_free_slabs;
    kmem_cache_ctor_t ctor;
    kmem_slab_alloc_fn_t slab_alloc_fn;
    kmem_slab_free_fn_t slab_free_fn;
    char name[KMEM_NAME_SIZE];
    size_t buftag_dist; /* Distance from buffer to buftag */
    size_t redzone_pad; /* Bytes from end of object to redzone word */
};

#endif /* _KERN_KMEM_I_H */
