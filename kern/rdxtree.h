/*
 * Copyright (c) 2011, 2013 Richard Braun.
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
 * Radix tree.
 *
 * In addition to the standard insertion operation, this implementation can
 * allocate keys for the caller at insertion time. It also allows lookups to
 * occur concurrently with updates through the use of lockless synchronization
 * (see the llsync module).
 */

#ifndef _KERN_RDXTREE_H
#define _KERN_RDXTREE_H

#include <kern/stddef.h>
#include <kern/rdxtree_i.h>

/*
 * Radix tree.
 */
struct rdxtree;

/*
 * Radix tree iterator.
 */
struct rdxtree_iter;

/*
 * Static tree initializer.
 */
#define RDXTREE_INITIALIZER { 0, NULL }

/*
 * Initialize a tree.
 */
static inline void
rdxtree_init(struct rdxtree *tree)
{
    tree->height = 0;
    tree->root = NULL;
}

/*
 * Insert a pointer in a tree.
 *
 * The ptr parameter must not be null.
 */
static inline int
rdxtree_insert(struct rdxtree *tree, unsigned long key, void *ptr)
{
    return rdxtree_insert_common(tree, key, ptr, NULL);
}

/*
 * Insert a pointer in a tree and obtain its slot.
 *
 * The ptr and slotp parameters must not be null. If successful, the slot of
 * the newly inserted pointer is stored at the address pointed to by the slotp
 * parameter.
 */
static inline int
rdxtree_insert_slot(struct rdxtree *tree, unsigned long key, void *ptr,
                    void ***slotp)
{
    return rdxtree_insert_common(tree, key, ptr, slotp);
}

/*
 * Insert a pointer in a tree, for which a new key is allocated.
 *
 * The ptr and keyp parameters must not be null. The newly allocated key is
 * stored at the address pointed to by the keyp parameter.
 */
static inline int
rdxtree_insert_alloc(struct rdxtree *tree, void *ptr, unsigned long *keyp)
{
    return rdxtree_insert_alloc_common(tree, ptr, keyp, NULL);
}

/*
 * Insert a pointer in a tree, for which a new key is allocated, and obtain
 * its slot.
 *
 * The ptr, keyp and slotp parameters must not be null. The newly allocated
 * key is stored at the address pointed to by the keyp parameter while the
 * slot of the inserted pointer is stored at the address pointed to by the
 * slotp parameter.
 */
static inline int
rdxtree_insert_alloc_slot(struct rdxtree *tree, void *ptr,
                          unsigned long *keyp, void ***slotp)
{
    return rdxtree_insert_alloc_common(tree, ptr, keyp, slotp);
}

/*
 * Remove a pointer from a tree.
 *
 * The matching pointer is returned if successful, null otherwise.
 */
void * rdxtree_remove(struct rdxtree *tree, unsigned long key);

/*
 * Look up a pointer in a tree.
 *
 * The matching pointer is returned if successful, null otherwise.
 *
 * This function can safely proceed while the tree is being concurrently
 * updated through the use of lockless synchronization.
 */
static inline void *
rdxtree_lookup(struct rdxtree *tree, unsigned long key)
{
    return rdxtree_lookup_common(tree, key, 0);
}

/*
 * Look up a slot in a tree.
 *
 * A slot is a pointer to a stored pointer in a tree. It can be used as
 * a placeholder for fast replacements to avoid multiple lookups on the same
 * key.
 *
 * A slot for the matching pointer is returned if successful, null otherwise.
 *
 * Unlike rdxtree_lookup(), the caller must synchronize access to the tree,
 * because otherwise, the slot might be made invalid by concurrent updates.
 *
 * See rdxtree_replace_slot().
 */
static inline void **
rdxtree_lookup_slot(struct rdxtree *tree, unsigned long key)
{
    return rdxtree_lookup_common(tree, key, 1);
}

/*
 * Replace a pointer in a tree.
 *
 * The ptr parameter must not be null. The previous pointer is returned.
 *
 * See rdxtree_lookup_slot().
 */
void * rdxtree_replace_slot(void **slot, void *ptr);

/*
 * Forge a loop to process all pointers of a tree.
 */
#define rdxtree_for_each(tree, iter, ptr)                           \
for (rdxtree_iter_init(iter), ptr = rdxtree_iter_next(tree, iter);  \
     ptr != NULL;                                                   \
     ptr = rdxtree_iter_next(tree, iter))

/*
 * Remove all pointers from a tree.
 *
 * The common way to destroy a tree and its pointers is to loop over all
 * the pointers using rdxtree_for_each(), freeing them, then call this
 * function.
 */
void rdxtree_remove_all(struct rdxtree *tree);

/*
 * Initialize the rdxtree module.
 */
void rdxtree_setup(void);

#endif /* _KERN_RDXTREE_H */
