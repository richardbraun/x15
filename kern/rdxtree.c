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
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <kern/assert.h>
#include <kern/error.h>
#include <kern/kmem.h>
#include <kern/limits.h>
#include <kern/llsync.h>
#include <kern/macros.h>
#include <kern/rdxtree.h>
#include <kern/rdxtree_i.h>
#include <kern/work.h>

/*
 * Mask applied on an entry to obtain its address.
 */
#define RDXTREE_ENTRY_ADDR_MASK (~0x3UL)

/*
 * Global properties used to shape radix trees.
 */
#define RDXTREE_RADIX       6
#define RDXTREE_RADIX_SIZE  (1UL << RDXTREE_RADIX)
#define RDXTREE_RADIX_MASK  (RDXTREE_RADIX_SIZE - 1)

#if RDXTREE_RADIX < 6
typedef unsigned long rdxtree_bm_t;
#define rdxtree_ffs(x) __builtin_ffsl(x)
#elif RDXTREE_RADIX == 6 /* RDXTREE_RADIX < 6 */
typedef unsigned long long rdxtree_bm_t;
#define rdxtree_ffs(x) __builtin_ffsll(x)
#else /* RDXTREE_RADIX < 6 */
#error "radix too high"
#endif /* RDXTREE_RADIX < 6 */

/*
 * Allocation bitmap size in bits.
 */
#define RDXTREE_BM_SIZE (sizeof(rdxtree_bm_t) * CHAR_BIT)

/*
 * Empty/full allocation bitmap words.
 */
#define RDXTREE_BM_EMPTY    ((rdxtree_bm_t)0)
#define RDXTREE_BM_FULL \
    ((~(rdxtree_bm_t)0) >> (RDXTREE_BM_SIZE - RDXTREE_RADIX_SIZE))

/*
 * Radix tree node.
 *
 * The height of a tree is the number of nodes to traverse until stored
 * pointers are reached. A height of 0 means the entries of a node (or the
 * tree root) directly point to stored pointers.
 *
 * The index is valid if and only if the parent isn't NULL.
 *
 * Concerning the allocation bitmap, a bit is set when the node it denotes,
 * or one of its children, can be used to allocate an entry. Conversely, a bit
 * is clear when the matching node and all of its children have no free entry.
 *
 * In order to support safe lockless lookups, in particular during a resize,
 * each node includes the height of its subtree, which is invariant during
 * the entire node lifetime. Since the tree height does vary, it can't be
 * used to determine whether the tree root is a node or a stored pointer.
 * This implementation assumes that all nodes and stored pointers are at least
 * 4-byte aligned, and uses the least significant bit of entries to indicate
 * the pointer type. This bit is set for internal nodes, and clear for stored
 * pointers so that they can be accessed from slots without conversion.
 */
struct rdxtree_node {
    union {
        struct {
            struct rdxtree_node *parent;
            unsigned short index;
        };

        /* Deferred destruction when unlinked */
        struct work work;
    };

    unsigned short height;
    unsigned short nr_entries;
    rdxtree_bm_t alloc_bm;
    void *entries[RDXTREE_RADIX_SIZE];
};

static struct kmem_cache rdxtree_node_cache;

static inline void
rdxtree_assert_alignment(const void *ptr)
{
    assert(((uintptr_t)ptr & ~RDXTREE_ENTRY_ADDR_MASK) == 0);
    (void)ptr;
}

static inline void *
rdxtree_entry_addr(void *entry)
{
    return (void *)((uintptr_t)entry & RDXTREE_ENTRY_ADDR_MASK);
}

static inline int
rdxtree_entry_is_node(const void *entry)
{
    return ((uintptr_t)entry & 1) != 0;
}

static inline void *
rdxtree_node_to_entry(struct rdxtree_node *node)
{
    return (void *)((uintptr_t)node | 1);
}

static void
rdxtree_node_ctor(void *buf)
{
    struct rdxtree_node *node;

    node = buf;
    node->nr_entries = 0;
    node->alloc_bm = RDXTREE_BM_FULL;
    memset(node->entries, 0, sizeof(node->entries));
}

static int
rdxtree_node_create(struct rdxtree_node **nodep, unsigned short height)
{
    struct rdxtree_node *node;

    node = kmem_cache_alloc(&rdxtree_node_cache);

    if (node == NULL) {
        return ERROR_NOMEM;
    }

    rdxtree_assert_alignment(node);
    node->parent = NULL;
    node->height = height;
    *nodep = node;
    return 0;
}

static void
rdxtree_node_destroy(struct rdxtree_node *node)
{
    /* See rdxtree_shrink() */
    if (node->nr_entries != 0) {
        assert(node->nr_entries == 1);
        assert(node->entries[0] != NULL);
        node->entries[0] = NULL;
        node->nr_entries = 0;
        node->alloc_bm = RDXTREE_BM_FULL;
    }

    kmem_cache_free(&rdxtree_node_cache, node);
}

static void
rdxtree_node_destroy_deferred(struct work *work)
{
    struct rdxtree_node *node;

    node = structof(work, struct rdxtree_node, work);
    rdxtree_node_destroy(node);
}

static void
rdxtree_node_schedule_destruction(struct rdxtree_node *node)
{
    assert(node->parent == NULL);

    work_init(&node->work, rdxtree_node_destroy_deferred);

    /*
     * This assumes that llsync is initialized before scheduling is started
     * so that there can be no read-side reference when destroying the node.
     */
    if (!llsync_ready()) {
        rdxtree_node_destroy(node);
        return;
    }

    llsync_defer(&node->work);
}

static inline void
rdxtree_node_link(struct rdxtree_node *node, struct rdxtree_node *parent,
                  unsigned short index)
{
    node->parent = parent;
    node->index = index;
}

static inline void
rdxtree_node_unlink(struct rdxtree_node *node)
{
    assert(node->parent != NULL);
    node->parent = NULL;
}

static inline int
rdxtree_node_full(struct rdxtree_node *node)
{
    return (node->nr_entries == ARRAY_SIZE(node->entries));
}

static inline int
rdxtree_node_empty(struct rdxtree_node *node)
{
    return (node->nr_entries == 0);
}

static inline void
rdxtree_node_insert(struct rdxtree_node *node, unsigned short index,
                    void *entry)
{
    assert(index < ARRAY_SIZE(node->entries));
    assert(node->entries[index] == NULL);

    node->nr_entries++;
    llsync_assign_ptr(node->entries[index], entry);
}

static inline void
rdxtree_node_insert_node(struct rdxtree_node *node, unsigned short index,
                         struct rdxtree_node *child)
{
    rdxtree_node_insert(node, index, rdxtree_node_to_entry(child));
}

static inline void
rdxtree_node_remove(struct rdxtree_node *node, unsigned short index)
{
    assert(index < ARRAY_SIZE(node->entries));
    assert(node->entries[index] != NULL);

    node->nr_entries--;
    llsync_assign_ptr(node->entries[index], NULL);
}

static inline void *
rdxtree_node_find(struct rdxtree_node *node, unsigned short *indexp)
{
    unsigned short index;
    void *ptr;

    index = *indexp;

    while (index < ARRAY_SIZE(node->entries)) {
        ptr = rdxtree_entry_addr(llsync_read_ptr(node->entries[index]));

        if (ptr != NULL) {
            *indexp = index;
            return ptr;
        }

        index++;
    }

    return NULL;
}

static inline void
rdxtree_node_bm_set(struct rdxtree_node *node, unsigned short index)
{
    node->alloc_bm |= (rdxtree_bm_t)1 << index;
}

static inline void
rdxtree_node_bm_clear(struct rdxtree_node *node, unsigned short index)
{
    node->alloc_bm &= ~((rdxtree_bm_t)1 << index);
}

static inline int
rdxtree_node_bm_is_set(struct rdxtree_node *node, unsigned short index)
{
    return (node->alloc_bm & ((rdxtree_bm_t)1 << index));
}

static inline int
rdxtree_node_bm_empty(struct rdxtree_node *node)
{
    return (node->alloc_bm == RDXTREE_BM_EMPTY);
}

static inline unsigned short
rdxtree_node_bm_first(struct rdxtree_node *node)
{
    return rdxtree_ffs(node->alloc_bm) - 1;
}

static inline rdxtree_key_t
rdxtree_max_key(unsigned short height)
{
    size_t shift;

    shift = RDXTREE_RADIX * height;

    if (likely(shift < (sizeof(rdxtree_key_t) * CHAR_BIT))) {
        return ((rdxtree_key_t)1 << shift) - 1;
    } else {
        return ~((rdxtree_key_t)0);
    }
}

static inline bool
rdxtree_key_alloc_enabled(const struct rdxtree *tree)
{
    return (tree->flags & RDXTREE_KEY_ALLOC);
}

static void
rdxtree_shrink(struct rdxtree *tree)
{
    struct rdxtree_node *node;
    void *entry;

    while (tree->height > 0) {
        node = rdxtree_entry_addr(tree->root);

        if (node->nr_entries != 1) {
            break;
        }

        entry = node->entries[0];

        if (entry == NULL) {
            break;
        }

        tree->height--;

        if (tree->height > 0) {
            rdxtree_node_unlink(rdxtree_entry_addr(entry));
        }

        llsync_assign_ptr(tree->root, entry);

        /*
         * There is still one valid entry (the first one) in this node. It
         * must remain valid as long as read-side references can exist so
         * that concurrent lookups can find the rest of the tree. Therefore,
         * this entry isn't reset before node destruction.
         */
        rdxtree_node_schedule_destruction(node);
    }
}

static int
rdxtree_grow(struct rdxtree *tree, rdxtree_key_t key)
{
    struct rdxtree_node *root, *node;
    unsigned short new_height;
    int error;

    new_height = tree->height + 1;

    while (key > rdxtree_max_key(new_height)) {
        new_height++;
    }

    if (tree->root == NULL) {
        tree->height = new_height;
        return 0;
    }

    root = rdxtree_entry_addr(tree->root);

    do {
        error = rdxtree_node_create(&node, tree->height);

        if (error) {
            rdxtree_shrink(tree);
            return error;
        }

        if (tree->height == 0) {
            if (rdxtree_key_alloc_enabled(tree)) {
                rdxtree_node_bm_clear(node, 0);
            }
        } else {
            rdxtree_node_link(root, node, 0);

            if (rdxtree_key_alloc_enabled(tree)
                && rdxtree_node_bm_empty(root)) {
                rdxtree_node_bm_clear(node, 0);
            }
        }

        rdxtree_node_insert(node, 0, tree->root);
        tree->height++;
        llsync_assign_ptr(tree->root, rdxtree_node_to_entry(node));
        root = node;
    } while (new_height > tree->height);

    return 0;
}

static void
rdxtree_cleanup(struct rdxtree *tree, struct rdxtree_node *node)
{
    struct rdxtree_node *prev;

    for (;;) {
        if (likely(!rdxtree_node_empty(node))) {
            if (unlikely(node->parent == NULL)) {
                rdxtree_shrink(tree);
            }

            break;
        }

        if (node->parent == NULL) {
            tree->height = 0;
            llsync_assign_ptr(tree->root, NULL);
            rdxtree_node_schedule_destruction(node);
            break;
        }

        prev = node;
        node = node->parent;
        rdxtree_node_unlink(prev);
        rdxtree_node_remove(node, prev->index);
        rdxtree_node_schedule_destruction(prev);
    }
}

static void
rdxtree_insert_bm_clear(struct rdxtree_node *node, unsigned short index)
{
    for (;;) {
        rdxtree_node_bm_clear(node, index);

        if (!rdxtree_node_full(node) || (node->parent == NULL)) {
            break;
        }

        index = node->index;
        node = node->parent;
    }
}

int
rdxtree_insert_common(struct rdxtree *tree, rdxtree_key_t key,
                      void *ptr, void ***slotp)
{
    struct rdxtree_node *node, *prev;
    unsigned short height, shift;
    unsigned short index = 0; /* GCC */
    int error;

    assert(ptr != NULL);
    rdxtree_assert_alignment(ptr);

    if (unlikely(key > rdxtree_max_key(tree->height))) {
        error = rdxtree_grow(tree, key);

        if (error) {
            return error;
        }
    }

    height = tree->height;

    if (unlikely(height == 0)) {
        if (tree->root != NULL) {
            return ERROR_BUSY;
        }

        llsync_assign_ptr(tree->root, ptr);

        if (slotp != NULL) {
            *slotp = &tree->root;
        }

        return 0;
    }

    node = rdxtree_entry_addr(tree->root);
    shift = (height - 1) * RDXTREE_RADIX;
    prev = NULL;

    do {
        if (node == NULL) {
            error = rdxtree_node_create(&node, height - 1);

            if (error) {
                if (prev == NULL) {
                    tree->height = 0;
                } else {
                    rdxtree_cleanup(tree, prev);
                }

                return error;
            }

            if (prev == NULL) {
                llsync_assign_ptr(tree->root, rdxtree_node_to_entry(node));
            } else {
                rdxtree_node_link(node, prev, index);
                rdxtree_node_insert_node(prev, index, node);
            }
        }

        prev = node;
        index = (unsigned short)(key >> shift) & RDXTREE_RADIX_MASK;
        node = rdxtree_entry_addr(prev->entries[index]);
        shift -= RDXTREE_RADIX;
        height--;
    } while (height > 0);

    if (unlikely(node != NULL)) {
        return ERROR_BUSY;
    }

    rdxtree_node_insert(prev, index, ptr);

    if (rdxtree_key_alloc_enabled(tree)) {
        rdxtree_insert_bm_clear(prev, index);
    }

    if (slotp != NULL) {
        *slotp = &prev->entries[index];
    }

    return 0;
}

int
rdxtree_insert_alloc_common(struct rdxtree *tree, void *ptr,
                            rdxtree_key_t *keyp, void ***slotp)
{
    struct rdxtree_node *node, *prev;
    unsigned short height, shift;
    unsigned short index = 0; /* GCC */
    rdxtree_key_t key;
    int error;

    assert(rdxtree_key_alloc_enabled(tree));
    assert(ptr != NULL);
    rdxtree_assert_alignment(ptr);

    height = tree->height;

    if (unlikely(height == 0)) {
        if (tree->root == NULL) {
            llsync_assign_ptr(tree->root, ptr);
            *keyp = 0;

            if (slotp != NULL) {
                *slotp = &tree->root;
            }

            return 0;
        }

        goto grow;
    }

    node = rdxtree_entry_addr(tree->root);
    key = 0;
    shift = (height - 1) * RDXTREE_RADIX;
    prev = NULL;

    do {
        if (node == NULL) {
            error = rdxtree_node_create(&node, height - 1);

            if (error) {
                rdxtree_cleanup(tree, prev);
                return error;
            }

            rdxtree_node_link(node, prev, index);
            rdxtree_node_insert_node(prev, index, node);
        }

        prev = node;
        index = rdxtree_node_bm_first(node);

        if (index == (unsigned short)-1) {
            goto grow;
        }

        key |= (rdxtree_key_t)index << shift;
        node = rdxtree_entry_addr(node->entries[index]);
        shift -= RDXTREE_RADIX;
        height--;
    } while (height > 0);

    rdxtree_node_insert(prev, index, ptr);
    rdxtree_insert_bm_clear(prev, index);

    if (slotp != NULL) {
        *slotp = &prev->entries[index];
    }

    goto out;

grow:
    key = rdxtree_max_key(height) + 1;
    error = rdxtree_insert_common(tree, key, ptr, slotp);

    if (error) {
        return error;
    }

out:
    *keyp = key;
    return 0;
}

static void
rdxtree_remove_bm_set(struct rdxtree_node *node, unsigned short index)
{
    do {
        rdxtree_node_bm_set(node, index);

        if (node->parent == NULL) {
            break;
        }

        index = node->index;
        node = node->parent;
    } while (!rdxtree_node_bm_is_set(node, index));
}

void *
rdxtree_remove(struct rdxtree *tree, rdxtree_key_t key)
{
    struct rdxtree_node *node, *prev;
    unsigned short height, shift, index;

    height = tree->height;

    if (unlikely(key > rdxtree_max_key(height))) {
        return NULL;
    }

    node = rdxtree_entry_addr(tree->root);

    if (unlikely(height == 0)) {
        llsync_assign_ptr(tree->root, NULL);
        return node;
    }

    shift = (height - 1) * RDXTREE_RADIX;

    do {
        if (node == NULL) {
            return NULL;
        }

        prev = node;
        index = (unsigned short)(key >> shift) & RDXTREE_RADIX_MASK;
        node = rdxtree_entry_addr(node->entries[index]);
        shift -= RDXTREE_RADIX;
        height--;
    } while (height > 0);

    if (node == NULL) {
        return NULL;
    }

    if (rdxtree_key_alloc_enabled(tree)) {
        rdxtree_remove_bm_set(prev, index);
    }

    rdxtree_node_remove(prev, index);
    rdxtree_cleanup(tree, prev);
    return node;
}

void *
rdxtree_lookup_common(const struct rdxtree *tree, rdxtree_key_t key,
                      int get_slot)
{
    struct rdxtree_node *node, *prev;
    unsigned short height, shift, index;
    void *entry;

    entry = llsync_read_ptr(tree->root);

    if (entry == NULL) {
        node = NULL;
        height = 0;
    } else {
        node = rdxtree_entry_addr(entry);
        height = rdxtree_entry_is_node(entry) ? node->height + 1 : 0;
    }

    if (key > rdxtree_max_key(height)) {
        return NULL;
    }

    if (height == 0) {
        if (node == NULL) {
            return NULL;
        }

        return get_slot ? (void *)&tree->root : node;
    }

    shift = (height - 1) * RDXTREE_RADIX;

    do {
        if (node == NULL) {
            return NULL;
        }

        prev = node;
        index = (unsigned short)(key >> shift) & RDXTREE_RADIX_MASK;
        entry = llsync_read_ptr(node->entries[index]);
        node = rdxtree_entry_addr(entry);
        shift -= RDXTREE_RADIX;
        height--;
    } while (height > 0);

    if (node == NULL) {
        return NULL;
    }

    return get_slot ? (void *)&prev->entries[index] : node;
}

void *
rdxtree_replace_slot(void **slot, void *ptr)
{
    void *old;

    assert(ptr != NULL);
    rdxtree_assert_alignment(ptr);

    old = *slot;
    assert(old != NULL);
    rdxtree_assert_alignment(old);
    llsync_assign_ptr(*slot, ptr);
    return old;
}

static void *
rdxtree_walk_next(struct rdxtree *tree, struct rdxtree_iter *iter)
{
    struct rdxtree_node *root, *node, *prev;
    unsigned short height, shift, index, orig_index;
    rdxtree_key_t key;
    void *entry;

    entry = llsync_read_ptr(tree->root);

    if (entry == NULL) {
        return NULL;
    }

    if (!rdxtree_entry_is_node(entry)) {
        if (iter->key != (rdxtree_key_t)-1) {
            return NULL;
        } else {
            iter->key = 0;
            return rdxtree_entry_addr(entry);
        }
    }

    key = iter->key + 1;

    if ((key == 0) && (iter->node != NULL)) {
        return NULL;
    }

    root = rdxtree_entry_addr(entry);

restart:
    node = root;
    height = root->height + 1;

    if (key > rdxtree_max_key(height)) {
        return NULL;
    }

    shift = (height - 1) * RDXTREE_RADIX;

    do {
        prev = node;
        index = (key >> shift) & RDXTREE_RADIX_MASK;
        orig_index = index;
        node = rdxtree_node_find(node, &index);

        if (node == NULL) {
            shift += RDXTREE_RADIX;
            key = ((key >> shift) + 1) << shift;

            if (key == 0) {
                return NULL;
            }

            goto restart;
        }

        if (orig_index != index) {
            key = ((key >> shift) + (index - orig_index)) << shift;
        }

        shift -= RDXTREE_RADIX;
        height--;
    } while (height > 0);

    iter->node = prev;
    iter->key = key;
    return node;
}

void *
rdxtree_walk(struct rdxtree *tree, struct rdxtree_iter *iter)
{
    unsigned short index, orig_index;
    void *ptr;

    if (iter->node == NULL) {
        return rdxtree_walk_next(tree, iter);
    }

    index = (iter->key + 1) & RDXTREE_RADIX_MASK;

    if (index != 0) {
        orig_index = index;
        ptr = rdxtree_node_find(iter->node, &index);

        if (ptr != NULL) {
            iter->key += (index - orig_index) + 1;
            return ptr;
        }
    }

    return rdxtree_walk_next(tree, iter);
}

void
rdxtree_remove_all(struct rdxtree *tree)
{
    struct rdxtree_node *node, *parent;
    struct rdxtree_iter iter;

    if (tree->height == 0) {
        if (tree->root != NULL) {
            llsync_assign_ptr(tree->root, NULL);
        }

        return;
    }

    for (;;) {
        rdxtree_iter_init(&iter);
        rdxtree_walk_next(tree, &iter);

        if (iter.node == NULL) {
            break;
        }

        node = iter.node;
        parent = node->parent;

        if (parent == NULL) {
            rdxtree_init(tree, tree->flags);
        } else {
            if (rdxtree_key_alloc_enabled(tree)) {
                rdxtree_remove_bm_set(parent, node->index);
            }

            rdxtree_node_remove(parent, node->index);
            rdxtree_cleanup(tree, parent);
            node->parent = NULL;
        }

        rdxtree_node_schedule_destruction(node);
    }
}

void
rdxtree_setup(void)
{
    kmem_cache_init(&rdxtree_node_cache, "rdxtree_node",
                    sizeof(struct rdxtree_node), 0,
                    rdxtree_node_ctor, 0);
}
