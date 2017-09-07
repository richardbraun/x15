/*
 * Copyright (c) 2011-2017 Richard Braun.
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

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <kern/error.h>
#include <kern/init.h>
#include <kern/kmem.h>
#include <kern/list.h>
#include <kern/macros.h>
#include <kern/mutex.h>
#include <kern/panic.h>
#include <kern/rbtree.h>
#include <kern/shell.h>
#include <kern/task.h>
#include <machine/page.h>
#include <machine/pmap.h>
#include <vm/vm_adv.h>
#include <vm/vm_inherit.h>
#include <vm/vm_map.h>
#include <vm/vm_kmem.h>
#include <vm/vm_page.h>
#include <vm/vm_prot.h>

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
    uintptr_t start;
    size_t size;
    size_t align;
    int flags;
    struct vm_object *object;
    uint64_t offset;
    struct vm_map_entry *next;
};

static int vm_map_prepare(struct vm_map *map, uintptr_t start,
                          size_t size, size_t align, int flags,
                          struct vm_object *object, uint64_t offset,
                          struct vm_map_request *request);

static int vm_map_insert(struct vm_map *map, struct vm_map_entry *entry,
                         const struct vm_map_request *request);

static struct kmem_cache vm_map_entry_cache;
static struct kmem_cache vm_map_cache;

struct vm_map vm_map_kernel_map;

static struct vm_map_entry *
vm_map_entry_create(void)
{
    struct vm_map_entry *entry;

    entry = kmem_cache_alloc(&vm_map_entry_cache);

    /* TODO Handle error */
    if (entry == NULL) {
        panic("vm_map: can't create map entry");
    }

    return entry;
}

static void
vm_map_entry_destroy(struct vm_map_entry *entry)
{
    kmem_cache_free(&vm_map_entry_cache, entry);
}

static inline int
vm_map_entry_cmp_lookup(uintptr_t addr, const struct rbtree_node *node)
{
    struct vm_map_entry *entry;

    entry = rbtree_entry(node, struct vm_map_entry, tree_node);

    if (addr >= entry->end) {
        return 1;
    }

    if (addr >= entry->start) {
        return 0;
    }

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

#ifndef NDEBUG
static void
vm_map_request_assert_valid(const struct vm_map_request *request)
{
    assert((request->object != NULL) || (request->offset == 0));
    assert(vm_page_aligned(request->offset));
    assert(vm_page_aligned(request->start));
    assert(request->size > 0);
    assert(vm_page_aligned(request->size));
    assert((request->start + request->size) > request->start);
    assert((request->align == 0) || (request->align >= PAGE_SIZE));
    assert(ISP2(request->align));

    assert((VM_MAP_PROT(request->flags) & VM_MAP_MAXPROT(request->flags))
           == VM_MAP_PROT(request->flags));
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
vm_map_lookup_nearest(struct vm_map *map, uintptr_t addr)
{
    struct vm_map_entry *entry;
    struct rbtree_node *node;

    assert(vm_page_aligned(addr));

    entry = map->lookup_cache;

    if ((entry != NULL) && (addr >= entry->start) && (addr < entry->end)) {
        return entry;
    }

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
    uintptr_t start;
    size_t size;

    start = request->start;
    size = request->size;

    if ((start < map->start) || (start + size) > map->end) {
        return ERROR_NOMEM;
    }

    next = vm_map_lookup_nearest(map, start);

    if (next == NULL) {
        if ((map->end - start) < size) {
            return ERROR_NOMEM;
        }

        request->next = NULL;
        return 0;
    }

    if ((start >= next->start) || ((next->start - start) < size)) {
        return ERROR_NOMEM;
    }

    request->next = next;
    return 0;
}

static int
vm_map_find_avail(struct vm_map *map, struct vm_map_request *request)
{
    struct vm_map_entry *next;
    struct list *node;
    uintptr_t base, start;
    size_t size, align, space;
    int error;

    /* If there is a hint, try there */
    if (request->start != 0) {
        error = vm_map_find_fixed(map, request);

        if (!error) {
            return 0;
        }
    }

    size = request->size;
    align = request->align;

    if (size > map->find_cache_threshold) {
        base = map->find_cache;
    } else {
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

        if (align != 0) {
            start = P2ROUND(start, align);
        }

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

        if (next == NULL) {
            space = map->end - start;
        } else if (start >= next->start) {
            space = 0;
        } else {
            space = next->start - start;
        }

        if (space >= size) {
            map->find_cache = start + size;
            request->start = start;
            request->next = next;
            return 0;
        }

        if (space > map->find_cache_threshold) {
            map->find_cache_threshold = space;
        }

        start = next->end;
        node = list_next(&next->list_node);

        if (list_end(&map->entry_list, node)) {
            next = NULL;
        } else {
            next = list_entry(node, struct vm_map_entry, list_node);
        }
    }
}

static inline struct vm_map_entry *
vm_map_next(struct vm_map *map, struct vm_map_entry *entry)
{
    struct list *node;

    node = list_next(&entry->list_node);

    if (list_end(&map->entry_list, node)) {
        return NULL;
    } else {
        return list_entry(node, struct vm_map_entry, list_node);
    }
}

static void
vm_map_link(struct vm_map *map, struct vm_map_entry *entry,
            struct vm_map_entry *next)
{
    assert(entry->start < entry->end);

    if (next == NULL) {
        list_insert_tail(&map->entry_list, &entry->list_node);
    } else {
        list_insert_before(&next->list_node, &entry->list_node);
    }

    rbtree_insert(&map->entry_tree, &entry->tree_node, vm_map_entry_cmp_insert);
    map->nr_entries++;
}

static void
vm_map_unlink(struct vm_map *map, struct vm_map_entry *entry)
{
    assert(entry->start < entry->end);

    if (map->lookup_cache == entry) {
        map->lookup_cache = NULL;
    }

    list_remove(&entry->list_node);
    rbtree_remove(&map->entry_tree, &entry->tree_node);
    map->nr_entries--;
}

/*
 * Check mapping parameters, find a suitable area of virtual memory, and
 * prepare the mapping request for that region.
 */
static int
vm_map_prepare(struct vm_map *map, uintptr_t start,
               size_t size, size_t align, int flags,
               struct vm_object *object, uint64_t offset,
               struct vm_map_request *request)
{
    int error;

    request->start = start;
    request->size = size;
    request->align = align;
    request->flags = flags;
    request->object = object;
    request->offset = offset;
    vm_map_request_assert_valid(request);

    if (flags & VM_MAP_FIXED) {
        error = vm_map_find_fixed(map, request);
    } else {
        error = vm_map_find_avail(map, request);
    }

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
vm_map_try_merge_compatible(const struct vm_map_request *request,
                            const struct vm_map_entry *entry)
{
    /* Only merge special kernel mappings for now */
    return (request->object == NULL)
           && (entry->object == NULL)
           && ((request->flags & VM_MAP_ENTRY_MASK)
               == (entry->flags & VM_MAP_ENTRY_MASK));
}

static struct vm_map_entry *
vm_map_try_merge_prev(struct vm_map *map, const struct vm_map_request *request,
                      struct vm_map_entry *entry)
{
    struct vm_map_entry *next;

    assert(entry != NULL);

    if (!vm_map_try_merge_compatible(request, entry)) {
        return NULL;
    }

    if (entry->end != request->start) {
        return NULL;
    }

    next = vm_map_next(map, entry);
    vm_map_unlink(map, entry);
    entry->end += request->size;
    vm_map_link(map, entry, next);
    return entry;
}

static struct vm_map_entry *
vm_map_try_merge_next(struct vm_map *map, const struct vm_map_request *request,
                      struct vm_map_entry *entry)
{
    struct vm_map_entry *next;
    uintptr_t end;

    assert(entry != NULL);

    if (!vm_map_try_merge_compatible(request, entry)) {
        return NULL;
    }

    end = request->start + request->size;

    if (end != entry->start) {
        return NULL;
    }

    next = vm_map_next(map, entry);
    vm_map_unlink(map, entry);
    entry->start = request->start;
    vm_map_link(map, entry, next);
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
        && vm_map_try_merge_compatible(request, first)
        && vm_map_try_merge_compatible(request, second)) {
        struct vm_map_entry *next;

        next = vm_map_next(map, second);
        vm_map_unlink(map, first);
        vm_map_unlink(map, second);
        first->end = second->end;
        vm_map_entry_destroy(second);
        vm_map_link(map, first, next);
        return first;
    }

    entry = vm_map_try_merge_prev(map, request, first);

    if (entry != NULL) {
        return entry;
    }

    return vm_map_try_merge_next(map, request, second);
}

static struct vm_map_entry *
vm_map_try_merge(struct vm_map *map, const struct vm_map_request *request)
{
    struct vm_map_entry *entry, *prev;
    struct list *node;

    /* Statically allocated map entries must not be merged */
    assert(!(request->flags & VM_MAP_NOMERGE));

    if (request->next == NULL) {
        node = list_last(&map->entry_list);

        if (list_end(&map->entry_list, node)) {
            entry = NULL;
        } else {
            prev = list_entry(node, struct vm_map_entry, list_node);
            entry = vm_map_try_merge_prev(map, request, prev);
        }
    } else {
        node = list_prev(&request->next->list_node);

        if (list_end(&map->entry_list, node)) {
            entry = vm_map_try_merge_next(map, request, request->next);
        } else {
            prev = list_entry(node, struct vm_map_entry, list_node);
            entry = vm_map_try_merge_near(map, request, prev, request->next);
        }
    }

    return entry;
}

/*
 * Convert a prepared mapping request into an entry in the given map.
 *
 * If entry is NULL, a map entry is allocated for the mapping.
 */
static int
vm_map_insert(struct vm_map *map, struct vm_map_entry *entry,
              const struct vm_map_request *request)
{
    if (entry == NULL) {
        entry = vm_map_try_merge(map, request);

        if (entry != NULL) {
            goto out;
        }

        entry = vm_map_entry_create();
    }

    entry->start = request->start;
    entry->end = request->start + request->size;
    entry->object = request->object;
    entry->offset = request->offset;
    entry->flags = request->flags & VM_MAP_ENTRY_MASK;
    vm_map_link(map, entry, request->next);

out:
    map->size += request->size;
    return 0;
}

int
vm_map_enter(struct vm_map *map, uintptr_t *startp,
             size_t size, size_t align, int flags,
             struct vm_object *object, uint64_t offset)
{
    struct vm_map_request request;
    int error;

    mutex_lock(&map->lock);

    error = vm_map_prepare(map, *startp, size, align, flags, object, offset,
                           &request);

    if (error) {
        goto error_enter;
    }

    error = vm_map_insert(map, NULL, &request);

    if (error) {
        goto error_enter;
    }

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
                     uintptr_t split_addr)
{
    uintptr_t delta;

    delta = split_addr - prev->start;
    prev->end = split_addr;
    next->start = split_addr;

    if (next->object != NULL) {
        next->offset += delta;
    }
}

static void
vm_map_clip_start(struct vm_map *map, struct vm_map_entry *entry,
                  uintptr_t start)
{
    struct vm_map_entry *new_entry, *next;

    if ((start <= entry->start) || (start >= entry->end)) {
        return;
    }

    next = vm_map_next(map, entry);
    vm_map_unlink(map, entry);
    new_entry = vm_map_entry_create();
    *new_entry = *entry;
    vm_map_split_entries(new_entry, entry, start);
    vm_map_link(map, entry, next);
    vm_map_link(map, new_entry, entry);
}

static void
vm_map_clip_end(struct vm_map *map, struct vm_map_entry *entry, uintptr_t end)
{
    struct vm_map_entry *new_entry, *next;

    if ((end <= entry->start) || (end >= entry->end)) {
        return;
    }

    next = vm_map_next(map, entry);
    vm_map_unlink(map, entry);
    new_entry = vm_map_entry_create();
    *new_entry = *entry;
    vm_map_split_entries(entry, new_entry, end);
    vm_map_link(map, entry, next);
    vm_map_link(map, new_entry, next);
}

void
vm_map_remove(struct vm_map *map, uintptr_t start, uintptr_t end)
{
    struct vm_map_entry *entry;
    struct list *node;

    assert(start >= map->start);
    assert(end <= map->end);
    assert(start < end);

    mutex_lock(&map->lock);

    entry = vm_map_lookup_nearest(map, start);

    if (entry == NULL) {
        goto out;
    }

    vm_map_clip_start(map, entry, start);

    while (entry->start < end) {
        vm_map_clip_end(map, entry, end);
        map->size -= entry->end - entry->start;
        node = list_next(&entry->list_node);
        vm_map_unlink(map, entry);

        /* TODO Defer destruction to shorten critical section */
        vm_map_entry_destroy(entry);

        if (list_end(&map->entry_list, node)) {
            break;
        }

        entry = list_entry(node, struct vm_map_entry, list_node);
    }

    vm_map_reset_find_cache(map);

out:
    mutex_unlock(&map->lock);
}

static void
vm_map_init(struct vm_map *map, struct pmap *pmap,
            uintptr_t start, uintptr_t end)
{
    assert(vm_page_aligned(start));
    assert(vm_page_aligned(end));
    assert(start < end);

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

#ifdef X15_ENABLE_SHELL

static void
vm_map_shell_info(int argc, char **argv)
{
    const struct task *task;

    if (argc < 2) {
        goto error;
    } else {
        task = task_lookup(argv[1]);

        if (task == NULL) {
            goto error;
        }

        vm_map_info(task_get_vm_map(task));
    }

    return;

error:
    printf("vm_map: info: invalid arguments\n");
}

static struct shell_cmd vm_map_shell_cmds[] = {
    SHELL_CMD_INITIALIZER("vm_map_info", vm_map_shell_info,
        "vm_map_info <task_name>",
        "display information about a VM map"),
};

static int __init
vm_map_setup_shell(void)
{
    SHELL_REGISTER_CMDS(vm_map_shell_cmds);
    return 0;
}

INIT_OP_DEFINE(vm_map_setup_shell,
               INIT_OP_DEP(mutex_setup, true),
               INIT_OP_DEP(printf_setup, true),
               INIT_OP_DEP(shell_setup, true),
               INIT_OP_DEP(task_setup, true),
               INIT_OP_DEP(vm_map_setup, true));

#endif /* X15_ENABLE_SHELL */

static int __init
vm_map_bootstrap(void)
{
    vm_map_init(vm_map_get_kernel_map(), pmap_get_kernel_pmap(),
                PMAP_START_KMEM_ADDRESS, PMAP_END_KMEM_ADDRESS);
    kmem_cache_init(&vm_map_entry_cache, "vm_map_entry",
                    sizeof(struct vm_map_entry), 0, NULL,
                    KMEM_CACHE_PAGE_ONLY);
    return 0;
}

INIT_OP_DEFINE(vm_map_bootstrap,
               INIT_OP_DEP(kmem_bootstrap, true),
               INIT_OP_DEP(thread_bootstrap, true));

static int __init
vm_map_setup(void)
{
    kmem_cache_init(&vm_map_cache, "vm_map", sizeof(struct vm_map),
                    0, NULL, KMEM_CACHE_PAGE_ONLY);
    return 0;
}

INIT_OP_DEFINE(vm_map_setup,
               INIT_OP_DEP(pmap_setup, true),
               INIT_OP_DEP(printf_setup, true),
               INIT_OP_DEP(vm_map_bootstrap, true));

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

    if (error) {
        goto error_pmap;
    }

    vm_map_init(map, pmap, PMAP_START_ADDRESS, PMAP_END_ADDRESS);
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

    if (map == vm_map_get_kernel_map()) {
        name = "kernel map";
    } else {
        name = "map";
    }

    mutex_lock(&map->lock);

    printf("vm_map: %s: %016lx-%016lx\n"
           "vm_map:      start             end          "
           "size     offset   flags    type\n", name,
           (unsigned long)map->start, (unsigned long)map->end);

    list_for_each_entry(&map->entry_list, entry, list_node) {
        if (entry->object == NULL) {
            type = "null";
        } else {
            type = "object";
        }

        printf("vm_map: %016lx %016lx %8luk %08llx %08x %s\n",
               (unsigned long)entry->start, (unsigned long)entry->end,
               (unsigned long)(entry->end - entry->start) >> 10,
               (unsigned long long)entry->offset, entry->flags, type);
    }

    printf("vm_map: total: %zuk\n", map->size >> 10);

    mutex_unlock(&map->lock);
}
