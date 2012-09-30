/*
 * Copyright (c) 2011, 2012 Richard Braun.
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
 */

#include <kern/error.h>
#include <kern/init.h>
#include <kern/kmem.h>
#include <kern/panic.h>
#include <kern/param.h>
#include <kern/printk.h>
#include <lib/assert.h>
#include <lib/list.h>
#include <lib/macros.h>
#include <lib/rbtree.h>
#include <lib/stddef.h>
#include <lib/stdint.h>
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
 * Statically allocated map entry for the first kernel map entry.
 */
static struct vm_map_entry vm_map_kernel_entry;

/*
 * Statically allocated map entry for the kernel map entry allocator.
 *
 * The purpose of this entry is to reserve virtual space for the kernel map
 * entries (those used in the kernel map). The reason is to avoid recursion,
 * as normal map entries are allocated from the kernel map (like any other
 * normal kernel object).
 */
static struct vm_map_entry vm_map_kentry_entry;

/*
 * Cache for the map entries used in the kernel map.
 */
static struct kmem_cache vm_map_kentry_cache;

/*
 * Cache for normal map entries.
 */
static struct kmem_cache vm_map_entry_cache;

/*
 * Address of the next free page available for kernel map entry allocation.
 */
static unsigned long vm_map_kentry_free;

/*
 * Allocate pages for the kernel map entry cache.
 */
static unsigned long
vm_map_kentry_pagealloc(size_t size)
{
    struct vm_page *page;
    unsigned long addr, va;

    assert(size > 0);
    assert(vm_page_aligned(size));

    if ((vm_map_kentry_entry.end - vm_map_kentry_free) < size)
        panic("vm_map: kentry cache pages exhausted");

    addr = vm_map_kentry_free;
    vm_map_kentry_free += size;

    for (va = addr; va < vm_map_kentry_free; va += PAGE_SIZE) {
        page = vm_phys_alloc(0);

        if (page == NULL)
            panic("vm_map: no physical page for kentry cache");

        pmap_kenter(va, vm_page_to_pa(page));
    }

    return addr;
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
    size_t size, space;
    int error;

    /* If there is a hint, try there */
    if (request->start != 0) {
        error = vm_map_find_fixed(map, request);

        if (!error)
            return 0;
    }

    size = request->size;

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

static void
vm_map_link(struct vm_map *map, struct vm_map_entry *entry,
            struct vm_map_entry *prev, struct vm_map_entry *next)
{
    assert((prev == NULL) || (next == NULL));

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
 * Convert a prepared mapping request into an entry in the given map.
 *
 * if entry is NULL, a map entry is allocated for the mapping.
 */
static int
vm_map_insert(struct vm_map *map, struct vm_map_entry *entry,
              const struct vm_map_request *request)
{
    /* TODO: merge/extend request with neighbors */

    if (entry == NULL)
        entry = vm_map_entry_create(map);

    entry->start = request->start;
    entry->end = request->start + request->size;
    entry->object = request->object;
    entry->offset = request->offset;
    entry->flags = request->flags & VM_MAP_ENTRY_MASK;
    vm_map_link(map, entry, NULL, request->next);
    map->size += request->size;

    if ((map == kernel_map) && (pmap_klimit < entry->end))
        pmap_growkernel(entry->end);

    return 0;
}

int
vm_map_enter(struct vm_map *map, struct vm_object *object, uint64_t offset,
             unsigned long *startp, size_t size, size_t align, int flags)
{
    struct vm_map_request request;
    int error;

    error = vm_map_prepare(map, object, offset, *startp, size, align, flags,
                           &request);

    if (error)
        goto error_enter;

    error = vm_map_insert(map, NULL, &request);

    if (error)
        goto error_enter;

    *startp = request.start;
    return 0;

error_enter:
    vm_map_reset_find_cache(map);
    return error;
}

static void
vm_map_split_entries(struct vm_map_entry *prev, struct vm_map_entry *next,
                     unsigned long split_addr)
{
    unsigned long diff;

    assert(prev->start < split_addr);
    assert(split_addr < prev->end);

    diff = split_addr - prev->start;
    prev->end = split_addr;
    next->start = split_addr;

    if (next->object != NULL)
        next->offset += diff;
}

static void
vm_map_clip_start(struct vm_map *map, struct vm_map_entry *entry,
                  unsigned long start)
{
    struct vm_map_entry *new_entry;

    if (entry->start >= start)
        return;

    new_entry = vm_map_entry_create(map);
    *new_entry = *entry;
    vm_map_split_entries(new_entry, entry, start);
    vm_map_link(map, new_entry, NULL, entry);
}

static void
vm_map_clip_end(struct vm_map *map, struct vm_map_entry *entry,
                unsigned long end)
{
    struct vm_map_entry *new_entry;

    if (entry->end <= end)
        return;

    new_entry = vm_map_entry_create(map);
    *new_entry = *entry;
    vm_map_split_entries(entry, new_entry, end);
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

    entry = vm_map_lookup_nearest(map, start);

    if (entry == NULL)
        return;

    vm_map_clip_start(map, entry, start);

    while (!list_end(&map->entry_list, &entry->list_node)
           && (entry->start < end)) {
        vm_map_clip_end(map, entry, end);
        map->size -= entry->end - entry->start;
        node = list_next(&entry->list_node);
        vm_map_unlink(map, entry);
        vm_map_entry_destroy(entry, map);
        entry = list_entry(node, struct vm_map_entry, list_node);
    }

    vm_map_reset_find_cache(map);
}

void
vm_map_init(struct vm_map *map, struct pmap *pmap, unsigned long start,
            unsigned long end)
{
    assert(vm_page_aligned(start));
    assert(vm_page_aligned(end));

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
vm_map_bootstrap(void)
{
    struct vm_map_request request;
    unsigned long start, end;
    int error, flags;

    vm_map_init(kernel_map, kernel_pmap, VM_MIN_KERNEL_ADDRESS,
                VM_MAX_KERNEL_ADDRESS);

    /*
     * Create the initial kernel mapping. This reserves memory for at least
     * the kernel image and the physical page table.
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

    /* Create the kentry mapping */
    flags = VM_MAP_PROT_ALL | VM_MAP_MAX_PROT_ALL | VM_MAP_INHERIT_NONE
            | VM_MAP_ADVISE_NORMAL | VM_MAP_NOMERGE;
    error = vm_map_prepare(kernel_map, NULL, 0, 0, VM_MAP_KENTRY_SIZE, 0,
                           flags, &request);

    if (error)
        panic("vm_map: kentry mapping setup failed");

    error = vm_map_insert(kernel_map, &vm_map_kentry_entry, &request);
    assert(!error);

    vm_map_kentry_free = vm_map_kentry_entry.start;

    flags = KMEM_CACHE_NOCPUPOOL | KMEM_CACHE_NOOFFSLAB | KMEM_CACHE_NORECLAIM;
    kmem_cache_init(&vm_map_kentry_cache, "vm_map_kentry",
                    sizeof(struct vm_map_entry), 0, NULL,
                    vm_map_kentry_pagealloc, NULL, flags);
}

void __init
vm_map_setup(void)
{
    kmem_cache_init(&vm_map_entry_cache, "vm_map_entry",
                    sizeof(struct vm_map_entry), 0, NULL, NULL, NULL, 0);
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

    printk("vm_map: %s: %08lx-%08lx\n", name, map->start, map->end);
    printk("vm_map:  start    end        size    offset   flags    type\n");

    list_for_each_entry(&map->entry_list, entry, list_node) {
        if (entry->object == NULL)
            type = "null";
        else
            type = "object";

        printk("vm_map: %08lx %08lx %8luk %08llx %08x %s\n", entry->start,
               entry->end, (entry->end - entry->start) >> 10, entry->offset,
               entry->flags, type);
    }

    printk("vm_map: total: %uk\n", map->size >> 10);
}
