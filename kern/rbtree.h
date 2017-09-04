/*
 * Copyright (c) 2010-2017 Richard Braun.
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
 * Red-black tree.
 */

#ifndef _KERN_RBTREE_H
#define _KERN_RBTREE_H

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include <kern/macros.h>

/*
 * Indexes of the left and right nodes in the children array of a node.
 */
#define RBTREE_LEFT     0
#define RBTREE_RIGHT    1

/*
 * Red-black node.
 */
struct rbtree_node;

/*
 * Red-black tree.
 */
struct rbtree;

/*
 * Insertion point identifier.
 */
typedef uintptr_t rbtree_slot_t;

/*
 * Static tree initializer.
 */
#define RBTREE_INITIALIZER { NULL }

#include <kern/rbtree_i.h>

/*
 * Initialize a tree.
 */
static inline void
rbtree_init(struct rbtree *tree)
{
    tree->root = NULL;
}

/*
 * Initialize a node.
 *
 * A node is in no tree when its parent points to itself.
 */
static inline void
rbtree_node_init(struct rbtree_node *node)
{
    assert(rbtree_node_check_alignment(node));

    node->parent = (uintptr_t)node | RBTREE_COLOR_RED;
    node->children[RBTREE_LEFT] = NULL;
    node->children[RBTREE_RIGHT] = NULL;
}

/*
 * Return true if node is in no tree.
 */
static inline int
rbtree_node_unlinked(const struct rbtree_node *node)
{
    return rbtree_node_parent(node) == node;
}

/*
 * Macro that evaluates to the address of the structure containing the
 * given node based on the given type and member.
 */
#define rbtree_entry(node, type, member) structof(node, type, member)

/*
 * Return true if tree is empty.
 */
static inline int
rbtree_empty(const struct rbtree *tree)
{
    return tree->root == NULL;
}

/*
 * Look up a node in a tree.
 *
 * Note that implementing the lookup algorithm as a macro gives two benefits:
 * First, it avoids the overhead of a callback function. Next, the type of the
 * cmp_fn parameter isn't rigid. The only guarantee offered by this
 * implementation is that the key parameter is the first parameter given to
 * cmp_fn. This way, users can pass only the value they need for comparison
 * instead of e.g. allocating a full structure on the stack.
 *
 * See rbtree_insert().
 */
#define rbtree_lookup(tree, key, cmp_fn)                \
MACRO_BEGIN                                             \
    struct rbtree_node *___cur;                         \
    int ___diff;                                        \
                                                        \
    ___cur = (tree)->root;                              \
                                                        \
    while (___cur != NULL) {                            \
        ___diff = cmp_fn(key, ___cur);                  \
                                                        \
        if (___diff == 0) {                             \
            break;                                      \
        }                                               \
                                                        \
        ___cur = ___cur->children[rbtree_d2i(___diff)]; \
    }                                                   \
                                                        \
    ___cur;                                             \
MACRO_END

/*
 * Look up a node or one of its nearest nodes in a tree.
 *
 * This macro essentially acts as rbtree_lookup() but if no entry matched
 * the key, an additional step is performed to obtain the next or previous
 * node, depending on the direction (left or right).
 *
 * The constraints that apply to the key parameter are the same as for
 * rbtree_lookup().
 */
#define rbtree_lookup_nearest(tree, key, cmp_fn, dir)       \
MACRO_BEGIN                                                 \
    struct rbtree_node *___cur, *___prev;                   \
    int ___diff, ___index;                                  \
                                                            \
    ___prev = NULL;                                         \
    ___index = -1;                                          \
    ___cur = (tree)->root;                                  \
                                                            \
    while (___cur != NULL) {                                \
        ___diff = cmp_fn(key, ___cur);                      \
                                                            \
        if (___diff == 0) {                                 \
            break;                                          \
        }                                                   \
                                                            \
        ___prev = ___cur;                                   \
        ___index = rbtree_d2i(___diff);                     \
        ___cur = ___cur->children[___index];                \
    }                                                       \
                                                            \
    if (___cur == NULL) {                                   \
        ___cur = rbtree_nearest(___prev, ___index, dir);    \
    }                                                       \
                                                            \
    ___cur;                                                 \
MACRO_END

/*
 * Insert a node in a tree.
 *
 * This macro performs a standard lookup to obtain the insertion point of
 * the given node in the tree (it is assumed that the inserted node never
 * compares equal to any other entry in the tree) and links the node. It
 * then checks red-black rules violations, and rebalances the tree if
 * necessary.
 *
 * Unlike rbtree_lookup(), the cmp_fn parameter must compare two complete
 * entries, so it is suggested to use two different comparison inline
 * functions, such as myobj_cmp_lookup() and myobj_cmp_insert(). There is no
 * guarantee about the order of the nodes given to the comparison function.
 *
 * See rbtree_lookup().
 */
#define rbtree_insert(tree, node, cmp_fn)                   \
MACRO_BEGIN                                                 \
    struct rbtree_node *___cur, *___prev;                   \
    int ___diff, ___index;                                  \
                                                            \
    ___prev = NULL;                                         \
    ___index = -1;                                          \
    ___cur = (tree)->root;                                  \
                                                            \
    while (___cur != NULL) {                                \
        ___diff = cmp_fn(node, ___cur);                     \
        assert(___diff != 0);                               \
        ___prev = ___cur;                                   \
        ___index = rbtree_d2i(___diff);                     \
        ___cur = ___cur->children[___index];                \
    }                                                       \
                                                            \
    rbtree_insert_rebalance(tree, ___prev, ___index, node); \
MACRO_END

/*
 * Look up a node/slot pair in a tree.
 *
 * This macro essentially acts as rbtree_lookup() but in addition to a node,
 * it also returns a slot, which identifies an insertion point in the tree.
 * If the returned node is NULL, the slot can be used by rbtree_insert_slot()
 * to insert without the overhead of an additional lookup.
 *
 * The constraints that apply to the key parameter are the same as for
 * rbtree_lookup().
 */
#define rbtree_lookup_slot(tree, key, cmp_fn, slot) \
MACRO_BEGIN                                         \
    struct rbtree_node *___cur, *___prev;           \
    int ___diff, ___index;                          \
                                                    \
    ___prev = NULL;                                 \
    ___index = 0;                                   \
    ___cur = (tree)->root;                          \
                                                    \
    while (___cur != NULL) {                        \
        ___diff = cmp_fn(key, ___cur);              \
                                                    \
        if (___diff == 0) {                         \
            break;                                  \
        }                                           \
                                                    \
        ___prev = ___cur;                           \
        ___index = rbtree_d2i(___diff);             \
        ___cur = ___cur->children[___index];        \
    }                                               \
                                                    \
    (slot) = rbtree_slot(___prev, ___index);        \
    ___cur;                                         \
MACRO_END

/*
 * Insert a node at an insertion point in a tree.
 *
 * This macro essentially acts as rbtree_insert() except that it doesn't
 * obtain the insertion point with a standard lookup. The insertion point
 * is obtained by calling rbtree_lookup_slot(). In addition, the new node
 * must not compare equal to an existing node in the tree (i.e. the slot
 * must denote a NULL node).
 */
static inline void
rbtree_insert_slot(struct rbtree *tree, rbtree_slot_t slot,
                   struct rbtree_node *node)
{
    struct rbtree_node *parent;
    int index;

    parent = rbtree_slot_parent(slot);
    index = rbtree_slot_index(slot);
    rbtree_insert_rebalance(tree, parent, index, node);
}

/*
 * Replace a node at an insertion point in a tree.
 *
 * The given node must compare strictly equal to the previous node,
 * which is returned on completion.
 */
void * rbtree_replace_slot(struct rbtree *tree, rbtree_slot_t slot,
                           struct rbtree_node *node);

/*
 * Remove a node from a tree.
 *
 * After completion, the node is stale.
 */
void rbtree_remove(struct rbtree *tree, struct rbtree_node *node);

/*
 * Return the first node of a tree.
 */
#define rbtree_first(tree) rbtree_firstlast(tree, RBTREE_LEFT)

/*
 * Return the last node of a tree.
 */
#define rbtree_last(tree) rbtree_firstlast(tree, RBTREE_RIGHT)

/*
 * Return the node previous to the given node.
 */
#define rbtree_prev(node) rbtree_walk(node, RBTREE_LEFT)

/*
 * Return the node next to the given node.
 */
#define rbtree_next(node) rbtree_walk(node, RBTREE_RIGHT)

/*
 * Forge a loop to process all nodes of a tree, removing them when visited.
 *
 * This macro can only be used to destroy a tree, so that the resources used
 * by the entries can be released by the user. It basically removes all nodes
 * without doing any color checking.
 *
 * After completion, all nodes and the tree root member are stale.
 */
#define rbtree_for_each_remove(tree, node, tmp)         \
for (node = rbtree_postwalk_deepest(tree),              \
     tmp = rbtree_postwalk_unlink(node);                \
     node != NULL;                                      \
     node = tmp, tmp = rbtree_postwalk_unlink(node))

#endif /* _KERN_RBTREE_H */
