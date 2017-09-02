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
 * Singly-linked list.
 */

#ifndef _KERN_SLIST_H
#define _KERN_SLIST_H

#include <stdbool.h>
#include <stddef.h>

#include <kern/llsync.h>
#include <kern/macros.h>
#include <kern/slist_types.h>

struct slist;

struct slist_node;

/*
 * Static list initializer.
 */
#define SLIST_INITIALIZER(list) { NULL, NULL }

/*
 * Initialize a list.
 */
static inline void
slist_init(struct slist *list)
{
    list->first = NULL;
    list->last = NULL;
}

/*
 * Return the first node of a list.
 */
static inline struct slist_node *
slist_first(const struct slist *list)
{
    return list->first;
}

/*
 * Return the last node of a list.
 */
static inline struct slist_node *
slist_last(const struct slist *list)
{
    return list->last;
}

/*
 * Return the node next to the given node.
 */
static inline struct slist_node *
slist_next(const struct slist_node *node)
{
    return node->next;
}

/*
 * Return true if node is invalid and denotes one of the ends of the list.
 */
static inline bool
slist_end(const struct slist_node *node)
{
    return node == NULL;
}

/*
 * Return true if list is empty.
 */
static inline bool
slist_empty(const struct slist *list)
{
    return list->first == NULL;
}

/*
 * Return true if list contains exactly one node.
 */
static inline bool
slist_singular(const struct slist *list)
{
    return !slist_empty(list) && (list->first == list->last);
}

/*
 * Append the nodes of list2 at the end of list1.
 *
 * After completion, list2 is stale.
 */
static inline void
slist_concat(struct slist *list1, const struct slist *list2)
{
    if (slist_empty(list2)) {
        return;
    }

    if (slist_empty(list1)) {
        list1->first = list2->first;
    } else {
        list1->last->next = list2->first;
    }

    list1->last = list2->last;
}

/*
 * Set the new head of a list.
 *
 * This function is an optimized version of :
 * list_init(&new_list);
 * list_concat(&new_list, &old_list);
 */
static inline void
slist_set_head(struct slist *new_head, const struct slist *old_head)
{
    *new_head = *old_head;
}

/*
 * Insert a node at the head of a list.
 */
static inline void
slist_insert_head(struct slist *list, struct slist_node *node)
{
    if (slist_empty(list)) {
        list->last = node;
    }

    node->next = list->first;
    list->first = node;
}

/*
 * Insert a node at the tail of a list.
 */
static inline void
slist_insert_tail(struct slist *list, struct slist_node *node)
{
    node->next = NULL;

    if (slist_empty(list)) {
        list->first = node;
    } else {
        list->last->next = node;
    }

    list->last = node;
}

/*
 * Insert a node after another node.
 *
 * The prev node must be valid.
 */
static inline void
slist_insert_after(struct slist *list, struct slist_node *prev,
                   struct slist_node *node)
{
    node->next = prev->next;
    prev->next = node;

    if (list->last == prev) {
        list->last = node;
    }
}

/*
 * Remove a node from a list.
 *
 * The prev argument must point to the node immediately preceding the target
 * node. It may safely denote the end of the given list, in which case the
 * first node is removed.
 */
static inline void
slist_remove(struct slist *list, struct slist_node *prev)
{
    struct slist_node *node;

    if (slist_end(prev)) {
        node = list->first;
        list->first = node->next;

        if (list->last == node) {
            list->last = NULL;
        }
    } else {
        node = prev->next;
        prev->next = node->next;

        if (list->last == node) {
            list->last = prev;
        }
    }
}

/*
 * Macro that evaluates to the address of the structure containing the
 * given node based on the given type and member.
 */
#define slist_entry(node, type, member) structof(node, type, member)

/*
 * Get the first entry of a list.
 */
#define slist_first_entry(list, type, member)                           \
MACRO_BEGIN                                                             \
    struct slist_node *___first;                                        \
                                                                        \
    ___first = (list)->first;                                           \
    slist_end(___first) ? NULL : slist_entry(___first, type, member);   \
MACRO_END

/*
 * Get the last entry of a list.
 */
#define slist_last_entry(list, type, member)                            \
MACRO_BEGIN                                                             \
    struct slist_node *___last;                                         \
                                                                        \
    ___last = (list)->last;                                             \
    slist_end(___last) ? NULL : slist_entry(___last, type, member);     \
MACRO_END

/*
 * Get the entry next to the given entry.
 */
#define slist_next_entry(entry, member) \
MACRO_BEGIN                                                             \
    struct slist_node *___next;                                         \
                                                                        \
    ___next = (entry)->member.next;                                     \
    slist_end(___next)                                                  \
        ? NULL                                                          \
        : slist_entry(___next, typeof(*entry), member);                 \
MACRO_END

/*
 * Forge a loop to process all nodes of a list.
 *
 * The node must not be altered during the loop.
 */
#define slist_for_each(list, node)  \
for (node = slist_first(list);      \
     !slist_end(node);              \
     node = slist_next(node))

/*
 * Forge a loop to process all nodes of a list.
 */
#define slist_for_each_safe(list, node, tmp)            \
for (node = slist_first(list),                          \
     tmp = slist_end(node) ? NULL : slist_next(node);   \
     !slist_end(node);                                  \
     node = tmp,                                        \
     tmp = slist_end(node) ? NULL : slist_next(node))

/*
 * Forge a loop to process all entries of a list.
 *
 * The entry node must not be altered during the loop.
 */
#define slist_for_each_entry(list, entry, member)               \
for (entry = slist_first_entry(list, typeof(*entry), member);   \
     entry != NULL;                                             \
     entry = slist_next_entry(entry, member))

/*
 * Forge a loop to process all entries of a list.
 */
#define slist_for_each_entry_safe(list, entry, tmp, member)             \
for (entry = slist_first_entry(list, typeof(*entry), member),           \
     tmp = (entry == NULL) ? NULL : slist_next_entry(entry, member);    \
     entry != NULL;                                                     \
     entry = tmp,                                                       \
     tmp = (entry == NULL) ? NULL : slist_next_entry(entry, member))    \

/*
 * Lockless variants
 *
 * The slist_end() function may be used from read-side critical sections.
 */

/*
 * Return the first node of a list.
 */
static inline struct slist_node *
slist_llsync_first(const struct slist *list)
{
    return llsync_load_ptr(list->first);
}

/*
 * Return the node next to the given node.
 */
static inline struct slist_node *
slist_llsync_next(const struct slist_node *node)
{
    return llsync_load_ptr(node->next);
}

/*
 * Insert a node at the head of a list.
 */
static inline void
slist_llsync_insert_head(struct slist *list, struct slist_node *node)
{
    if (slist_empty(list)) {
        list->last = node;
    }

    node->next = list->first;
    llsync_store_ptr(list->first, node);
}

/*
 * Insert a node at the tail of a list.
 */
static inline void
slist_llsync_insert_tail(struct slist *list, struct slist_node *node)
{
    node->next = NULL;

    if (slist_empty(list)) {
        llsync_store_ptr(list->first, node);
    } else {
        llsync_store_ptr(list->last->next, node);
    }

    list->last = node;
}

/*
 * Insert a node after another node.
 *
 * The prev node must be valid.
 */
static inline void
slist_llsync_insert_after(struct slist *list, struct slist_node *prev,
                          struct slist_node *node)
{
    node->next = prev->next;
    llsync_store_ptr(prev->next, node);

    if (list->last == prev) {
        list->last = node;
    }
}

/*
 * Remove a node from a list.
 *
 * The prev argument must point to the node immediately preceding the target
 * node. It may safely denote the end of the given list, in which case the
 * first node is removed.
 */
static inline void
slist_llsync_remove(struct slist *list, struct slist_node *prev)
{
    struct slist_node *node;

    if (slist_end(prev)) {
        node = list->first;
        llsync_store_ptr(list->first, node->next);

        if (list->last == node) {
            list->last = NULL;
        }
    } else {
        node = prev->next;
        llsync_store_ptr(prev->next, node->next);

        if (list->last == node) {
            list->last = prev;
        }
    }
}

/*
 * Macro that evaluates to the address of the structure containing the
 * given node based on the given type and member.
 */
#define slist_llsync_entry(node, type, member) \
    structof(llsync_load_ptr(node), type, member)

/*
 * Get the first entry of a list.
 */
#define slist_llsync_first_entry(list, type, member)                    \
MACRO_BEGIN                                                             \
    struct slist_node *___first;                                        \
                                                                        \
    ___first = slist_llsync_first(list);                                \
    slist_end(___first) ? NULL : slist_entry(___first, type, member);   \
MACRO_END

/*
 * Get the entry next to the given entry.
 */
#define slist_llsync_next_entry(entry, member)                          \
MACRO_BEGIN                                                             \
    struct slist_node *___next;                                         \
                                                                        \
    ___next = slist_llsync_next(&entry->member);                        \
    slist_end(___next)                                                  \
        ? NULL                                                          \
        : slist_entry(___next, typeof(*entry), member);                 \
MACRO_END

/*
 * Forge a loop to process all nodes of a list.
 */
#define slist_llsync_for_each(list, node)   \
for (node = slist_llsync_first(list);       \
     !slist_end(node);                      \
     node = slist_llsync_next(node))

/*
 * Forge a loop to process all entries of a list.
 */
#define slist_llsync_for_each_entry(list, entry, member)                \
for (entry = slist_llsync_first_entry(list, typeof(*entry), member);    \
     entry != NULL;                                                     \
     entry = slist_llsync_next_entry(entry, member))

#endif /* _KERN_SLIST_H */
