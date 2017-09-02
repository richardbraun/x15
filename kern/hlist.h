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
 * Doubly-linked list specialized for forward traversals and O(1) removals.
 */

#ifndef _KERN_HLIST_H
#define _KERN_HLIST_H

#include <stdbool.h>
#include <stddef.h>

#include <kern/hlist_types.h>
#include <kern/llsync.h>
#include <kern/macros.h>

struct hlist;

struct hlist_node;

/*
 * Static list initializer.
 */
#define HLIST_INITIALIZER(list) { NULL }

/*
 * Initialize a list.
 */
static inline void
hlist_init(struct hlist *list)
{
    list->first = NULL;
}

/*
 * Initialize a list node.
 *
 * A node is in no list when its pprev member points to NULL.
 */
static inline void
hlist_node_init(struct hlist_node *node)
{
    node->pprev = NULL;
}

/*
 * Return true if node is in no list.
 */
static inline bool
hlist_node_unlinked(const struct hlist_node *node)
{
    return node->pprev == NULL;
}

/*
 * Return the first node of a list.
 */
static inline struct hlist_node *
hlist_first(const struct hlist *list)
{
    return list->first;
}

/*
 * Return the node next to the given node.
 */
static inline struct hlist_node *
hlist_next(const struct hlist_node *node)
{
    return node->next;
}

/*
 * Return true if node is invalid and denotes the end of the list.
 */
static inline bool
hlist_end(const struct hlist_node *node)
{
    return node == NULL;
}

/*
 * Return true if list is empty.
 */
static inline bool
hlist_empty(const struct hlist *list)
{
    return list->first == NULL;
}

/*
 * Return true if list contains exactly one node.
 */
static inline bool
hlist_singular(const struct hlist *list)
{
    return !hlist_empty(list) && hlist_end(list->first->next);
}

/*
 * Set the new head of a list.
 *
 * After completion, old_head is stale.
 */
static inline void
hlist_set_head(struct hlist *new_head, const struct hlist *old_head)
{
    *new_head = *old_head;

    if (!hlist_empty(new_head)) {
        new_head->first->pprev = &new_head->first;
    }
}

/*
 * Insert a node at the head of a list.
 */
static inline void
hlist_insert_head(struct hlist *list, struct hlist_node *node)
{
    struct hlist_node *first;

    first = list->first;
    node->next = first;
    node->pprev = &list->first;

    if (first != NULL) {
        first->pprev = &node->next;
    }

    list->first = node;
}

/*
 * Insert a node before another node.
 */
static inline void
hlist_insert_before(struct hlist_node *next, struct hlist_node *node)
{
    node->next = next;
    node->pprev = next->pprev;
    next->pprev = &node->next;
    *node->pprev = node;
}

/*
 * Insert a node after another node.
 */
static inline void
hlist_insert_after(struct hlist_node *prev, struct hlist_node *node)
{
    node->next = prev->next;
    node->pprev = &prev->next;

    if (node->next != NULL) {
        node->next->pprev = &node->next;
    }

    prev->next = node;
}

/*
 * Remove a node from a list.
 */
static inline void
hlist_remove(struct hlist_node *node)
{
    if (node->next != NULL) {
        node->next->pprev = node->pprev;
    }

    *node->pprev = node->next;
}

/*
 * Macro that evaluates to the address of the structure containing the
 * given node based on the given type and member.
 */
#define hlist_entry(node, type, member) structof(node, type, member)

/*
 * Get the first entry of a list.
 */
#define hlist_first_entry(list, type, member)                           \
MACRO_BEGIN                                                             \
    struct hlist_node *___first;                                        \
                                                                        \
    ___first = (list)->first;                                           \
    hlist_end(___first) ? NULL : hlist_entry(___first, type, member);   \
MACRO_END

/*
 * Get the entry next to the given entry.
 */
#define hlist_next_entry(entry, member) \
MACRO_BEGIN                                                             \
    struct hlist_node *___next;                                         \
                                                                        \
    ___next = (entry)->member.next;                                     \
    hlist_end(___next)                                                  \
        ? NULL                                                          \
        : hlist_entry(___next, typeof(*entry), member);                 \
MACRO_END

/*
 * Forge a loop to process all nodes of a list.
 *
 * The node must not be altered during the loop.
 */
#define hlist_for_each(list, node)  \
for (node = hlist_first(list);      \
     !hlist_end(node);              \
     node = hlist_next(node))

/*
 * Forge a loop to process all nodes of a list.
 */
#define hlist_for_each_safe(list, node, tmp)            \
for (node = hlist_first(list),                          \
     tmp = hlist_end(node) ? NULL : hlist_next(node);   \
     !hlist_end(node);                                  \
     node = tmp,                                        \
     tmp = hlist_end(node) ? NULL : hlist_next(node))

/*
 * Forge a loop to process all entries of a list.
 *
 * The entry node must not be altered during the loop.
 */
#define hlist_for_each_entry(list, entry, member)               \
for (entry = hlist_first_entry(list, typeof(*entry), member);   \
     entry != NULL;                                             \
     entry = hlist_next_entry(entry, member))

/*
 * Forge a loop to process all entries of a list.
 */
#define hlist_for_each_entry_safe(list, entry, tmp, member)             \
for (entry = hlist_first_entry(list, typeof(*entry), member),           \
     tmp = (entry == NULL) ? NULL : hlist_next_entry(entry, member);    \
     entry != NULL;                                                     \
     entry = tmp,                                                       \
     tmp = (entry == NULL) ? NULL : hlist_next_entry(entry, member))    \

/*
 * Lockless variants
 *
 * The hlist_end() function may be used from read-side critical sections.
 */

/*
 * Return the first node of a list.
 */
static inline struct hlist_node *
hlist_llsync_first(const struct hlist *list)
{
    return llsync_load_ptr(list->first);
}

/*
 * Return the node next to the given node.
 */
static inline struct hlist_node *
hlist_llsync_next(const struct hlist_node *node)
{
    return llsync_load_ptr(node->next);
}

/*
 * Insert a node at the head of a list.
 */
static inline void
hlist_llsync_insert_head(struct hlist *list, struct hlist_node *node)
{
    struct hlist_node *first;

    first = list->first;
    node->next = first;
    node->pprev = &list->first;

    if (first != NULL) {
        first->pprev = &node->next;
    }

    llsync_store_ptr(list->first, node);
}

/*
 * Insert a node before another node.
 */
static inline void
hlist_llsync_insert_before(struct hlist_node *next, struct hlist_node *node)
{
    node->next = next;
    node->pprev = next->pprev;
    next->pprev = &node->next;
    llsync_store_ptr(*node->pprev, node);
}

/*
 * Insert a node after another node.
 */
static inline void
hlist_llsync_insert_after(struct hlist_node *prev, struct hlist_node *node)
{
    node->next = prev->next;
    node->pprev = &prev->next;

    if (node->next != NULL) {
        node->next->pprev = &node->next;
    }

    llsync_store_ptr(prev->next, node);
}

/*
 * Remove a node from a list.
 */
static inline void
hlist_llsync_remove(struct hlist_node *node)
{
    if (node->next != NULL) {
        node->next->pprev = node->pprev;
    }

    llsync_store_ptr(*node->pprev, node->next);
}

/*
 * Macro that evaluates to the address of the structure containing the
 * given node based on the given type and member.
 */
#define hlist_llsync_entry(node, type, member) \
    structof(llsync_load_ptr(node), type, member)

/*
 * Get the first entry of a list.
 */
#define hlist_llsync_first_entry(list, type, member)                    \
MACRO_BEGIN                                                             \
    struct hlist_node *___first;                                        \
                                                                        \
    ___first = hlist_llsync_first(list);                                \
    hlist_end(___first) ? NULL : hlist_entry(___first, type, member);   \
MACRO_END

/*
 * Get the entry next to the given entry.
 */
#define hlist_llsync_next_entry(entry, member)                          \
MACRO_BEGIN                                                             \
    struct hlist_node *___next;                                         \
                                                                        \
    ___next = hlist_llsync_next(&entry->member);                        \
    hlist_end(___next)                                                  \
        ? NULL                                                          \
        : hlist_entry(___next, typeof(*entry), member);                 \
MACRO_END

/*
 * Forge a loop to process all nodes of a list.
 */
#define hlist_llsync_for_each(list, node)   \
for (node = hlist_llsync_first(list);       \
     !hlist_end(node);                      \
     node = hlist_llsync_next(node))

/*
 * Forge a loop to process all entries of a list.
 */
#define hlist_llsync_for_each_entry(list, entry, member)                \
for (entry = hlist_llsync_first_entry(list, typeof(*entry), member);    \
     entry != NULL;                                                     \
     entry = hlist_llsync_next_entry(entry, member))

#endif /* _KERN_HLIST_H */
