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
 * Upstream site with license notes :
 * http://git.sceen.net/rbraun/librbraun.git/
 *
 *
 * Priority list.
 *
 * This container acts as a doubly-linked list sorted by priority in
 * ascending order. All operations behave as with a regular linked list
 * except insertion, which is O(k), k being the number of priorities
 * among the entries.
 */

#ifndef KERN_PLIST_H
#define KERN_PLIST_H

#include <stdbool.h>

#include <kern/list.h>
#include <kern/macros.h>
#include <kern/plist_types.h>

/*
 * Priority list.
 */
struct plist;

/*
 * Priority list node.
 */
struct plist_node;

/*
 * Static priority list initializer.
 */
#define PLIST_INITIALIZER(plist) \
    { LIST_INITIALIZER((plist).list), LIST_INITIALIZER((plist).prio_list) }

/*
 * Initialize a priority list.
 */
static inline void
plist_init(struct plist *plist)
{
    list_init(&plist->list);
    list_init(&plist->prio_list);
}

/*
 * Initialize a priority list node.
 */
static inline void
plist_node_init(struct plist_node *pnode, unsigned int priority)
{
    pnode->priority = priority;
    list_node_init(&pnode->node);
    list_node_init(&pnode->prio_node);
}

/*
 * Return the priority associated with a node.
 */
static inline unsigned int
plist_node_priority(const struct plist_node *pnode)
{
    return pnode->priority;
}

/*
 * Update the priority of an already initialized node.
 */
static inline void
plist_node_set_priority(struct plist_node *pnode, unsigned int priority)
{
    pnode->priority = priority;
}

/*
 * Return true if pnode is in no priority lists.
 */
static inline bool
plist_node_unlinked(const struct plist_node *pnode)
{
    return list_node_unlinked(&pnode->node);
}

/*
 * Macro that evaluates to the address of the structure containing the
 * given node based on the given type and member.
 */
#define plist_entry(pnode, type, member) structof(pnode, type, member)

/*
 * Return the first node of a priority list.
 */
static inline struct plist_node *
plist_first(const struct plist *plist)
{
    return list_first_entry(&plist->list, struct plist_node, node);
}

/*
 * Return the last node of a priority list.
 */
static inline struct plist_node *
plist_last(const struct plist *plist)
{
    return list_last_entry(&plist->list, struct plist_node, node);
}

/*
 * Return the node next to the given node.
 */
static inline struct plist_node *
plist_next(const struct plist_node *pnode)
{
    return (struct plist_node *)list_next_entry(pnode, node);
}

/*
 * Return the node previous to the given node.
 */
static inline struct plist_node *
plist_prev(const struct plist_node *pnode)
{
    return (struct plist_node *)list_prev_entry(pnode, node);
}

/*
 * Get the first entry of a priority list.
 */
#define plist_first_entry(plist, type, member) \
    plist_entry(plist_first(plist), type, member)

/*
 * Get the last entry of a priority list.
 */
#define plist_last_entry(plist, type, member) \
    plist_entry(plist_last(plist), type, member)

/*
 * Get the entry next to the given entry.
 */
#define plist_next_entry(entry, member) \
    plist_entry(plist_next(&(entry)->member), typeof(*(entry)), member)

/*
 * Get the entry previous to the given entry.
 */
#define plist_prev_entry(entry, member) \
    plist_entry(plist_prev(&(entry)->member), typeof(*(entry)), member)

/*
 * Return true if node is after the last or before the first node of
 * a priority list.
 */
static inline bool
plist_end(const struct plist *plist, const struct plist_node *pnode)
{
    return list_end(&plist->list, &pnode->node);
}

/*
 * Return true if plist is empty.
 */
static inline bool
plist_empty(const struct plist *plist)
{
    return list_empty(&plist->list);
}

/*
 * Return true if plist contains exactly one node.
 */
static inline bool
plist_singular(const struct plist *plist)
{
    return list_singular(&plist->list);
}

/*
 * Add a node to a priority list.
 *
 * If the priority list already contains nodes with the same priority
 * as the given node, it is inserted before them.
 *
 * The node must be initialized before calling this function.
 */
void plist_add(struct plist *plist, struct plist_node *pnode);

/*
 * Remove a node from a priority list.
 *
 * After completion, the node is stale.
 */
void plist_remove(struct plist *plist, struct plist_node *pnode);

/*
 * Forge a loop to process all nodes of a priority list.
 *
 * The node must not be altered during the loop.
 */
#define plist_for_each(plist, pnode)    \
for (pnode = plist_first(plist);        \
     !plist_end(plist, pnode);          \
     pnode = plist_next(pnode))

/*
 * Forge a loop to process all nodes of a priority list.
 */
#define plist_for_each_safe(plist, pnode, tmp)              \
for (pnode = plist_first(plist), tmp = plist_next(pnode);   \
     !plist_end(plist, pnode);                              \
     pnode = tmp, tmp = plist_next(pnode))

/*
 * Version of plist_for_each() that processes nodes backward.
 */
#define plist_for_each_reverse(plist, pnode)    \
for (pnode = plist_last(plist);                 \
     !plist_end(plist, pnode);                  \
     pnode = plist_prev(pnode))

/*
 * Version of plist_for_each_safe() that processes nodes backward.
 */
#define plist_for_each_reverse_safe(plist, pnode, tmp)      \
for (pnode = plist_last(plist), tmp = plist_prev(pnode);    \
     !plist_end(plist, pnode);                              \
     pnode = tmp, tmp = plist_prev(pnode))

/*
 * Forge a loop to process all entries of a priority list.
 *
 * The entry node must not be altered during the loop.
 */
#define plist_for_each_entry(plist, entry, member) \
    list_for_each_entry(&(plist)->list, entry, member.node)

/*
 * Forge a loop to process all entries of a priority list.
 */
#define plist_for_each_entry_safe(plist, entry, tmp, member) \
    list_for_each_entry_safe(&(plist)->list, entry, tmp, member.node)

/*
 * Version of plist_for_each_entry() that processes entries backward.
 */
#define plist_for_each_entry_reverse(plist, entry, member) \
    list_for_each_entry_reverse(&(plist)->list, entry, member.node)

/*
 * Version of plist_for_each_entry_safe() that processes entries backward.
 */
#define plist_for_each_entry_reverse_safe(plist, entry, tmp, member) \
    list_for_each_entry_reverse_safe(&(plist)->list, entry, tmp, member.node)

#endif /* KERN_PLIST_H */
