/*
 * Copyright (c) 2011, 2012, 2013 Richard Braun.
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
 * XXX This module is far from complete. It just provides the basic support
 * needed for kernel allocation.
 *
 *
 * In order to avoid recursion on memory allocation (allocating memory may
 * require allocating memory), kernel map entries are allocated out of a
 * special pool called the kentry area, which is used as the backend for
 * the kernel map entries kmem cache. This virtual area has a fixed size
 * and is preallocated at boot time (a single map entry reserves the whole
 * range). To manage slabs inside the kentry area, a table is also preallocated
 * at the end of the kentry area. Each entry in this table describes a slab
 * (either free or used by the slab allocator). Free slabs are linked together
 * in a simple free list.
 */

#include <kern/assert.h>
#include <kern/error.h>
#include <kern/init.h>
#include <kern/kmem.h>
#include <kern/list.h>
#include <kern/macros.h>
#include <kern/mutex.h>
#include <kern/panic.h>
#include <kern/param.h>
#include <kern/printk.h>
#include <kern/rbtree.h>
#include <kern/stddef.h>
#include <kern/stdint.h>
#include <machine/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_kmem.h>
#include <vm/vm_page.h>
#include <vm/vm_phys.h>

/*
 * Special threshold which disables the use of the free area cache address.
 */
#define VM_MAP_NO_FIND_CACHE (~(size_t)0)

/*
 * Mapping request.
 *
 * Most members are input parameters from a call to e.g. vm_map_enter(). The
 * start member is also an output argument. The next member is used internally
 * by the mapping functions.
 */
struct vm_map_request {
    struct vm_object *object;
    unsigned long offset;
    unsigned long start;
    size_t size;
    size_t align;
    int flags;
    struct vm_map_entry *next;
};

/*
 * TODO Common memory patterns.
 */
#define VM_MAP_KENTRY_ALLOCATED ((struct vm_map_kentry_slab *)0xa110c8edUL)

/*
 * Slab descriptor in the kentry table.
 */
struct vm_map_kentry_slab {
    struct vm_map_kentry_slab *next;
};

static int vm_map_prepare(struct vm_map *map, struct vm_object *object,
                          unsigned long offset, unsigned long start,
                          size_t size, size_t align, int flags,
                          struct vm_map_request *request);

static int vm_map_insert(struct vm_map *map, struct vm_map_entry *entry,
                         const struct vm_map_request *request);

/*
 * Statically allocated map entry for the first kernel map entry.
 */
static struct vm_map_entry vm_map_kernel_entry;

/*
 * Statically allocated map entry for the kentry area.
 */
static struct vm_map_entry vm_map_kentry_entry;

/*
 * Kentry slab free list.
 */
static struct mutex vm_map_kentry_free_slabs_lock;
static struct vm_map_kentry_slab *vm_map_kentry_free_slabs;

#ifdef NDEBUG
#define vm_map_kentry_slab_size 0
#else /* NDEBUG */
static size_t vm_map_kentry_slab_size;
#endif /* NDEBUG */

/*
 * Cache for kernel map entries.
 */
static struct kmem_cache vm_map_kentry_cache;

/*
 * Caches for normal map entries and maps.
 */
static struct kmem_cache vm_map_entry_cache;
static struct kmem_cache vm_map_cache;

static struct vm_map_kentry_slab *
vm_map_kentry_alloc_slab(void)
{
    struct vm_map_kentry_slab *slab;

    if (vm_map_kentry_free_slabs == NULL)
        panic("vm_map: kentry area exhausted");

    mutex_lock(&vm_map_kentry_free_slabs_lock);
    slab = vm_map_kentry_free_slabs;
    vm_map_kentry_free_slabs = slab->next;
    mutex_unlock(&vm_map_kentry_free_slabs_lock);

    assert(slab->next != VM_MAP_KENTRY_ALLOCATED);
    slab->next = VM_MAP_KENTRY_ALLOCATED;
    return slab;
}

static void
vm_map_kentry_free_slab(struct vm_map_kentry_slab *slab)
{
    assert(slab->next == VM_MAP_KENTRY_ALLOCATED);

    mutex_lock(&vm_map_kentry_free_slabs_lock);
    slab->next = vm_map_kentry_free_slabs;
    vm_map_kentry_free_slabs = slab;
    mutex_unlock(&vm_map_kentry_free_slabs_lock);
}

static struct vm_map_kentry_slab *
vm_map_kentry_slab_table(void)
{
    unsigned long va;

    va = vm_map_kentry_entry.start + VM_MAP_KENTRY_SIZE;
    return (struct vm_map_kentry_slab *)va;
}

static unsigned long
vm_map_kentry_alloc_va(size_t slab_size)
{
    struct vm_map_kentry_slab *slabs, *slab;
    unsigned long va;

    slabs = vm_map_kentry_slab_table();
    slab = vm_map_kentry_alloc_slab();
    va = vm_map_kentry_entry.start + ((slab - slabs) * slab_size);
    return va;
}

static void
vm_map_kentry_free_va(unsigned long va, size_t slab_size)
{
    struct vm_map_kentry_slab *slabs, *slab;

    slabs = vm_map_kentry_slab_table();
    slab = &slabs[(va - vm_map_kentry_entry.start) / slab_size];
    vm_map_kentry_free_slab(slab);
}

static unsigned long
vm_map_kentry_alloc(size_t slab_size)
{
    struct vm_page *page;
    unsigned long va;
    size_t i;

    assert(slab_size == vm_map_kentry_slab_size);

    va = vm_map_kentry_alloc_va(slab_size);
    assert(va >= vm_map_kentry_entry.start);
    assert((va + slab_size) <= (vm_map_kentry_entry.start
                                + VM_MAP_KENTRY_SIZE));

    for (i = 0; i < slab_size; i += PAGE_SIZE) {
        page = vm_phys_alloc(0);

        if (page == NULL)
            panic("vm_map: no physical page for kentry cache");

        pmap_kenter(va + i, vm_page_to_pa(page));
    }

    pmap_kupdate(va, va + slab_size);
    return va;
}

static void
vm_map_kentry_free(unsigned long va, size_t slab_size)
{
    struct vm_page *page;
    phys_addr_t pa;
    size_t i;

    assert(va >= vm_map_kentry_entry.start);
    assert((va + slab_size) <= (vm_map_kentry_entry.start
                                + VM_MAP_KENTRY_SIZE));
    assert(slab_size == vm_map_kentry_slab_size);

    for (i = 0; i < slab_size; i += PAGE_SIZE) {
        pa = pmap_kextract(va + i);
        assert(pa != 0);
        page = vm_phys_lookup_page(pa);
        assert(page != NULL);
        vm_phys_free(page, 0);
    }

    pmap_kremove(va, va + slab_size);
    pmap_kupdate(va, va + slab_size);
    vm_map_kentry_free_va(va, slab_size);
}

static void __init
vm_map_kentry_setup(void)
{
    struct vm_map_request request;
    struct vm_map_kentry_slab *slabs;
    struct vm_page *page;
    size_t i, nr_slabs, size, nr_pages;
    unsigned long table_va;
    int error, flags;

    flags = KMEM_CACHE_NOCPUPOOL | KMEM_CACHE_NOOFFSLAB;
    kmem_cache_init(&vm_map_kentry_cache, "vm_map_kentry",
                    sizeof(struct vm_map_entry), 0, NULL,
                    vm_map_kentry_alloc, vm_map_kentry_free, flags);

    size = kmem_cache_slab_size(&vm_map_kentry_cache);
#ifndef NDEBUG
    vm_map_kentry_slab_size = size;
#endif /* NDEBUG */
    nr_slabs = VM_MAP_KENTRY_SIZE / size;
    assert(nr_slabs > 0);
    size = vm_page_round(nr_slabs * sizeof(struct vm_map_kentry_slab));
    nr_pages = size / PAGE_SIZE;
    assert(nr_pages > 0);

    assert(vm_page_aligned(VM_MAP_KENTRY_SIZE));
    flags = VM_MAP_PROT_ALL | VM_MAP_MAX_PROT_ALL | VM_MAP_INHERIT_NONE
            | VM_MAP_ADVISE_NORMAL | VM_MAP_NOMERGE;
    error = vm_map_prepare(kernel_map, NULL, 0, 0, VM_MAP_KENTRY_SIZE + size,
                           0, flags, &request);

    if (error)
        panic("vm_map: kentry mapping setup failed");

    error = vm_map_insert(kernel_map, &vm_map_kentry_entry, &request);
    assert(!error);

    table_va = vm_map_kentry_entry.start + VM_MAP_KENTRY_SIZE;

    for (i = 0; i < nr_pages; i++) {
        page = vm_phys_alloc(0);

        if (page == NULL)
            panic("vm_map: unable to allocate page for kentry table");

        pmap_kenter(table_va + (i * PAGE_SIZE), vm_page_to_pa(page));
    }

    pmap_kupdate(table_va, table_va + (nr_pages * PAGE_SIZE));

    mutex_init(&vm_map_kentry_free_slabs_lock);
    slabs = (struct vm_map_kentry_slab *)table_va;
    vm_map_kentry_free_slabs = &slabs[nr_slabs - 1];
    vm_map_kentry_free_slabs->next = NULL;

    for (i = nr_slabs - 2; i < nr_slabs; i--) {
        slabs[i].next = vm_map_kentry_free_slabs;
        vm_map_kentry_free_slabs = &slabs[i];
    }
}

static inline struct kmem_cache *
vm_map_entry_select_cache(const struct vm_map *map)
{
    return (map == kernel_map) ? &vm_map_kentry_cache : &vm_map_entry_cache;
}

static struct vm_map_entry *
vm_map_entry_create(const struct vm_map *map)
{
    struct vm_map_entry *entry;

    entry = kmem_cache_alloc(vm_map_entry_select_cache(map));

    if (entry == NULL)
        panic("vm_map: can't create map entry");

    return entry;
}

static void
vm_map_entry_destroy(struct vm_map_entry *entry, const struct vm_map *map)
{
    kmem_cache_free(vm_map_entry_select_cache(map), entry);
}

static inline int
vm_map_entry_cmp_lookup(unsigned long addr, const struct rbtree_node *node)
{
    struct vm_map_entry *entry;

    entry = rbtree_entry(node, struct vm_map_entry, tree_node);

    if (addr >= entry->end)
        return 1;

    if (addr >= entry->start)
        return 0;

    return -1;
}

static inline int
vm_map_entry_cmp_insert(const struct rbtree_node *a,
                        const struct rbtree_node *b)
{
    struct vm_map_entry *entry;

    entry = rbtree_entry(a, struct vm_map_entry, tree_node);
    return vm_map_entry_cmp_lookup(entry->start, b);
}

static inline int
vm_map_get_protection(int flags)
{
    return flags & VM_MAP_PROT_MASK;
}

static inline int
vm_map_get_max_protection(int flags)
{
    return (flags & VM_MAP_MAX_PROT_MASK) >> 4;
}

#ifndef NDEBUG
static void
vm_map_request_assert_valid(const struct vm_map_request *request)
{
    int prot, max_prot;

    assert((request->object != NULL) || (request->offset == 0));
    assert(vm_page_aligned(request->offset));
    assert(vm_page_aligned(request->start));
    assert(request->size > 0);
    assert(vm_page_aligned(request->size));
    assert((request->start + request->size) > request->start);
    assert((request->align == 0) || (request->align >= PAGE_SIZE));
    assert(ISP2(request->align));

    prot = vm_map_get_protection(request->flags);
    max_prot = vm_map_get_max_protection(request->flags);
    assert((prot & max_prot) == prot);
    assert(__builtin_popcount(request->flags & VM_MAP_INHERIT_MASK) == 1);
    assert(__builtin_popcount(request->flags & VM_MAP_ADVISE_MASK) == 1);
    assert(!(request->flags & VM_MAP_FIXED)
           || (request->align == 0)
           || P2ALIGNED(request->start, request->align));
}
#else /* NDEBUG */
#define vm_map_request_assert_valid(request)
#endif /* NDEBUG */

/*
 * Look up an entry in a map.
 *
 * This function returns the entry which is closest to the given address
 * such that addr < entry->end (i.e. either containing or after the requested
 * address), or NULL if there is no such entry.
 */
static struct vm_map_entry *
vm_map_lookup_nearest(struct vm_map *map, unsigned long addr)
{
    struct vm_map_entry *entry;
    struct rbtree_node *node;

    assert(vm_page_aligned(addr));

    entry = map->lookup_cache;

    if ((entry != NULL) && (addr >= entry->start) && (addr < entry->end))
        return entry;

    node = rbtree_lookup_nearest(&map->entry_tree, addr,
                                 vm_map_entry_cmp_lookup, RBTREE_RIGHT);

    if (node != NULL) {
        entry = rbtree_entry(node, struct vm_map_entry, tree_node);
        assert(addr < entry->end);
        map->lookup_cache = entry;
        return entry;
    }

    return NULL;
}

static void
vm_map_reset_find_cache(struct vm_map *map)
{
    map->find_cache = 0;
    map->find_cache_threshold = VM_MAP_NO_FIND_CACHE;
}

static int
vm_map_find_fixed(struct vm_map *map, struct vm_map_request *request)
{
    struct vm_map_entry *next;
    unsigned long start;
    size_t size;

    start = request->start;
    size = request->size;

    if ((start < map->start) || (start + size) > map->end)
        return ERROR_NOMEM;

    next = vm_map_lookup_nearest(map, start);

    if (next == NULL) {
        if ((map->end - start) < size)
            return ERROR_NOMEM;

        request->next = NULL;
        return 0;
    }

    if ((start >= next->start) || ((next->start - start) < size))
        return ERROR_NOMEM;

    request->next = next;
    return 0;
}

static int
vm_map_find_avail(struct vm_map *map, struct vm_map_request *request)
{
    struct vm_map_entry *next;
    struct list *node;
    unsigned long base, start;
    size_t size, align, space;
    int error;

    /* If there is a hint, try there */
    if (request->start != 0) {
        error = vm_map_find_fixed(map, request);

        if (!error)
            return 0;
    }

    size = request->size;
    align = request->align;

    if (size > map->find_cache_threshold)
        base = map->find_cache;
    else {
        base = map->start;

        /*
         * Searching from the map start means the area which size is the
         * threshold (or a smaller one) may be selected, making the threshold
         * invalid. Reset it.
         */
        map->find_cache_threshold = 0;
    }

retry:
    start = base;
    next = vm_map_lookup_nearest(map, start);

    for (;;) {
        assert(start <= map->end);

        if (align != 0)
            start = P2ROUND(start, align);

        /*
         * The end of the map has been reached, and no space could be found.
         * If the search didn't start at map->start, retry from there in case
         * space is available below the previous start address.
         */
        if ((map->end - start) < size) {
            if (base != map->start) {
                base = map->start;
                map->find_cache_threshold = 0;
                goto retry;
            }

            return ERROR_NOMEM;
        }

        if (next == NULL)
            space = map->end - start;
        else if (start >= next->start)
            space = 0;
        else
            space = next->start - start;

        if (space >= size) {
            map->find_cache = start + size;
            request->start = start;
            request->next = next;
            return 0;
        }

        if (space > map->find_cache_threshold)
            map->find_cache_threshold = space;

        start = next->end;
        node = list_next(&next->list_node);

        if (list_end(&map->entry_list, node))
            next = NULL;
        else
            next = list_entry(node, struct vm_map_entry, list_node);
    }
}

static inline struct vm_map_entry *
vm_map_prev(struct vm_map *map, struct vm_map_entry *entry)
{
    struct list *node;

    node = list_prev(&entry->list_node);

    if (list_end(&map->entry_list, node))
        return NULL;
    else
        return list_entry(node, struct vm_map_entry, list_node);
}

static inline struct vm_map_entry *
vm_map_next(struct vm_map *map, struct vm_map_entry *entry)
{
    struct list *node;

    node = list_next(&entry->list_node);

    if (list_end(&map->entry_list, node))
        return NULL;
    else
        return list_entry(node, struct vm_map_entry, list_node);
}

static void
vm_map_link(struct vm_map *map, struct vm_map_entry *entry,
            struct vm_map_entry *prev, struct vm_map_entry *next)
{
    assert(entry->start < entry->end);

    if ((prev == NULL) && (next == NULL))
        list_insert_tail(&map->entry_list, &entry->list_node);
    else if (prev == NULL)
        list_insert_before(&next->list_node, &entry->list_node);
    else
        list_insert_after(&prev->list_node, &entry->list_node);

    rbtree_insert(&map->entry_tree, &entry->tree_node, vm_map_entry_cmp_insert);
    map->nr_entries++;
}

static void
vm_map_unlink(struct vm_map *map, struct vm_map_entry *entry)
{
    assert(entry->start < entry->end);

    list_remove(&entry->list_node);
    rbtree_remove(&map->entry_tree, &entry->tree_node);
    map->nr_entries--;
}

/*
 * Check mapping parameters, find a suitable area of virtual memory, and
 * prepare the mapping request for that region.
 */
static int
vm_map_prepare(struct vm_map *map, struct vm_object *object, unsigned long offset,
               unsigned long start, size_t size, size_t align, int flags,
               struct vm_map_request *request)
{
    int error;

    request->object = object;
    request->offset = offset;
    request->start = start;
    request->size = size;
    request->align = align;
    request->flags = flags;
    vm_map_request_assert_valid(request);

    if (flags & VM_MAP_FIXED)
        error = vm_map_find_fixed(map, request);
    else
        error = vm_map_find_avail(map, request);

    return error;
}

/*
 * Merging functions.
 *
 * There is room for optimization (e.g. not reinserting entries when it is
 * known the tree doesn't need to be adjusted), but focus on correctness for
 * now.
 */

static inline int
vm_map_try_merge_compatible(int flags1, int flags2)
{
    return (flags1 & VM_MAP_ENTRY_MASK) == (flags2 & VM_MAP_ENTRY_MASK);
}

static struct vm_map_entry *
vm_map_try_merge_prev(struct vm_map *map, const struct vm_map_request *request,
                      struct vm_map_entry *entry)
{
    struct vm_map_entry *prev, *next;

    assert(entry != NULL);

    if (!vm_map_try_merge_compatible(entry->flags, request->flags))
        return NULL;

    if (entry->end != request->start)
        return NULL;

    prev = vm_map_prev(map, entry);
    next = vm_map_next(map, entry);
    vm_map_unlink(map, entry);
    entry->end += request->size;
    vm_map_link(map, entry, prev, next);
    return entry;
}

static struct vm_map_entry *
vm_map_try_merge_next(struct vm_map *map, const struct vm_map_request *request,
                      struct vm_map_entry *entry)
{
    struct vm_map_entry *prev, *next;
    unsigned long end;

    assert(entry != NULL);

    if (!vm_map_try_merge_compatible(entry->flags, request->flags))
        return NULL;

    end = request->start + request->size;

    if (end != entry->start)
        return NULL;

    prev = vm_map_prev(map, entry);
    next = vm_map_next(map, entry);
    vm_map_unlink(map, entry);
    entry->start = request->start;
    vm_map_link(map, entry, prev, next);
    return entry;
}

static struct vm_map_entry *
vm_map_try_merge_near(struct vm_map *map, const struct vm_map_request *request,
                      struct vm_map_entry *first, struct vm_map_entry *second)
{
    struct vm_map_entry *entry;

    assert(first != NULL);
    assert(second != NULL);

    if ((first->end == request->start)
        && ((request->start + request->size) == second->start)
        && vm_map_try_merge_compatible(first->flags, request->flags)
        && vm_map_try_merge_compatible(request->flags, second->flags)) {
        struct vm_map_entry *prev, *next;

        prev = vm_map_prev(map, first);
        next = vm_map_next(map, second);
        vm_map_unlink(map, first);
        vm_map_unlink(map, second);
        first->end = second->end;
        vm_map_entry_destroy(second, map);
        vm_map_link(map, first, prev, next);
        return first;
    }

    entry = vm_map_try_merge_prev(map, request, first);

    if (entry != NULL)
        return entry;

    return vm_map_try_merge_next(map, request, second);
}

static struct vm_map_entry *
vm_map_try_merge(struct vm_map *map, const struct vm_map_request *request)
{
    struct vm_map_entry *entry, *prev;
    struct list *node;

    assert(!(request->flags & VM_MAP_NOMERGE));

    /* Only merge special kernel mappings for now */
    if (request->object != NULL)
        return NULL;

    if (request->next == NULL) {
        node = list_last(&map->entry_list);

        if (list_end(&map->entry_list, node))
            entry = NULL;
        else {
            prev = list_entry(node, struct vm_map_entry, list_node);
            entry = vm_map_try_merge_prev(map, request, prev);
        }
    } else {
        node = list_prev(&request->next->list_node);

        if (list_end(&map->entry_list, node))
            entry = vm_map_try_merge_next(map, request, request->next);
        else {
            prev = list_entry(node, struct vm_map_entry, list_node);
            entry = vm_map_try_merge_near(map, request, prev, request->next);
        }
    }

    return entry;
}

/*
 * Convert a prepared mapping request into an entry in the given map.
 *
 * if entry is NULL, a map entry is allocated for the mapping.
 */
static int
vm_map_insert(struct vm_map *map, struct vm_map_entry *entry,
              const struct vm_map_request *request)
{
    if (entry == NULL) {
        entry = vm_map_try_merge(map, request);

        if (entry != NULL)
            goto out;

        entry = vm_map_entry_create(map);
    }

    entry->start = request->start;
    entry->end = request->start + request->size;
    entry->object = request->object;
    entry->offset = request->offset;
    entry->flags = request->flags & VM_MAP_ENTRY_MASK;
    vm_map_link(map, entry, NULL, request->next);

out:
    map->size += request->size;

    if ((map == kernel_map) && (pmap_klimit() < entry->end))
        pmap_kgrow(entry->end);

    return 0;
}

int
vm_map_enter(struct vm_map *map, struct vm_object *object, uint64_t offset,
             unsigned long *startp, size_t size, size_t align, int flags)
{
    struct vm_map_request request;
    int error;

    mutex_lock(&map->lock);

    error = vm_map_prepare(map, object, offset, *startp, size, align, flags,
                           &request);

    if (error)
        goto error_enter;

    error = vm_map_insert(map, NULL, &request);

    if (error)
        goto error_enter;

    mutex_unlock(&map->lock);

    *startp = request.start;
    return 0;

error_enter:
    vm_map_reset_find_cache(map);
    mutex_unlock(&map->lock);
    return error;
}

static void
vm_map_split_entries(struct vm_map_entry *prev, struct vm_map_entry *next,
                     unsigned long split_addr)
{
    unsigned long delta;

    delta = split_addr - prev->start;
    prev->end = split_addr;
    next->start = split_addr;

    if (next->object != NULL)
        next->offset += delta;
}

static void
vm_map_clip_start(struct vm_map *map, struct vm_map_entry *entry,
                  unsigned long start)
{
    struct vm_map_entry *new_entry, *next;

    if ((start <= entry->start) || (start >= entry->end))
        return;

    next = vm_map_next(map, entry);
    vm_map_unlink(map, entry);
    new_entry = vm_map_entry_create(map);
    *new_entry = *entry;
    vm_map_split_entries(new_entry, entry, start);
    vm_map_link(map, entry, NULL, next);
    vm_map_link(map, new_entry, NULL, entry);
}

static void
vm_map_clip_end(struct vm_map *map, struct vm_map_entry *entry,
                unsigned long end)
{
    struct vm_map_entry *new_entry, *prev;

    if ((end <= entry->start) || (end >= entry->end))
        return;

    prev = vm_map_prev(map, entry);
    vm_map_unlink(map, entry);
    new_entry = vm_map_entry_create(map);
    *new_entry = *entry;
    vm_map_split_entries(entry, new_entry, end);
    vm_map_link(map, entry, prev, NULL);
    vm_map_link(map, new_entry, entry, NULL);
}

void
vm_map_remove(struct vm_map *map, unsigned long start, unsigned long end)
{
    struct vm_map_entry *entry;
    struct list *node;

    assert(start >= map->start);
    assert(end <= map->end);
    assert(start < end);

    mutex_lock(&map->lock);

    entry = vm_map_lookup_nearest(map, start);

    if (entry == NULL)
        goto out;

    vm_map_clip_start(map, entry, start);

    while (entry->start < end) {
        vm_map_clip_end(map, entry, end);
        map->size -= entry->end - entry->start;
        node = list_next(&entry->list_node);
        vm_map_unlink(map, entry);

        /* TODO Defer destruction to shorten critical section */
        vm_map_entry_destroy(entry, map);

        if (list_end(&map->entry_list, node))
            break;

        entry = list_entry(node, struct vm_map_entry, list_node);
    }

    vm_map_reset_find_cache(map);

out:
    mutex_unlock(&map->lock);
}

static void
vm_map_init(struct vm_map *map, struct pmap *pmap, unsigned long start,
            unsigned long end)
{
    assert(vm_page_aligned(start));
    assert(vm_page_aligned(end));

    mutex_init(&map->lock);
    list_init(&map->entry_list);
    rbtree_init(&map->entry_tree);
    map->nr_entries = 0;
    map->start = start;
    map->end = end;
    map->size = 0;
    map->lookup_cache = NULL;
    vm_map_reset_find_cache(map);
    map->pmap = pmap;
}

void __init
vm_map_setup(void)
{
    struct vm_map_request request;
    unsigned long start, end;
    int error, flags;

    vm_map_init(kernel_map, kernel_pmap, VM_MIN_KERNEL_ADDRESS,
                VM_MAX_KERNEL_ADDRESS);

    /*
     * Create the initial kernel mapping. This reserves memory for at least
     * the physical page table.
     */
    vm_kmem_boot_space(&start, &end);
    flags = VM_MAP_PROT_ALL | VM_MAP_MAX_PROT_ALL | VM_MAP_INHERIT_NONE
            | VM_MAP_ADVISE_NORMAL | VM_MAP_NOMERGE | VM_MAP_FIXED;
    error = vm_map_prepare(kernel_map, NULL, 0, start, end - start, 0, flags,
                           &request);

    if (error)
        panic("vm_map: can't map initial kernel mapping");

    error = vm_map_insert(kernel_map, &vm_map_kernel_entry, &request);
    assert(!error);

    vm_map_kentry_setup();

    kmem_cache_init(&vm_map_entry_cache, "vm_map_entry",
                    sizeof(struct vm_map_entry), 0, NULL, NULL, NULL, 0);
    kmem_cache_init(&vm_map_cache, "vm_map", sizeof(struct vm_map),
                    0, NULL, NULL, NULL, 0);
}

int
vm_map_create(struct vm_map **mapp)
{
    struct vm_map *map;
    struct pmap *pmap;
    int error;

    map = kmem_cache_alloc(&vm_map_cache);

    if (map == NULL) {
        error = ERROR_NOMEM;
        goto error_map;
    }

    error = pmap_create(&pmap);

    if (error)
        goto error_pmap;

    vm_map_init(map, pmap, VM_MIN_ADDRESS, VM_MAX_ADDRESS);
    *mapp = map;
    return 0;

error_pmap:
    kmem_cache_free(&vm_map_cache, map);
error_map:
    return error;
}

void
vm_map_info(struct vm_map *map)
{
    struct vm_map_entry *entry;
    const char *type, *name;

    if (map == kernel_map)
        name = "kernel map";
    else
        name = "map";

    printk("vm_map: %s: %016lx-%016lx\n"
           "vm_map:      start             end          "
           "size     offset   flags    type\n", name, map->start, map->end);

    list_for_each_entry(&map->entry_list, entry, list_node) {
        if (entry->object == NULL)
            type = "null";
        else
            type = "object";

        printk("vm_map: %016lx %016lx %8luk %08llx %08x %s\n", entry->start,
               entry->end, (entry->end - entry->start) >> 10, entry->offset,
               entry->flags, type);
    }

    printk("vm_map: total: %zuk\n", map->size >> 10);
}
