/*
 * Copyright (c) 2013 Richard Braun.
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

#ifndef _KERN_RDXTREE_I_H
#define _KERN_RDXTREE_I_H

/*
 * Radix tree.
 */
struct rdxtree {
    unsigned int height;
    void *root;
};

/*
 * Radix tree iterator.
 */
struct rdxtree_iter {
    void *node;
    void **slot;
};

/*
 * Initialize an iterator.
 */
static inline void
rdxtree_iter_init(struct rdxtree_iter *iter)
{
    iter->node = NULL;
    iter->slot = NULL;
}

int rdxtree_insert_common(struct rdxtree *tree, unsigned long long key,
                          void *ptr, void ***slotp);

int rdxtree_insert_alloc_common(struct rdxtree *tree, void *ptr,
                                unsigned long long *keyp, void ***slotp);

void * rdxtree_lookup_common(const struct rdxtree *tree, unsigned long long key,
                             int get_slot);

/*
 * Walk over pointers in a tree.
 *
 * Move the iterator to the next pointer in the given tree.
 *
 * The next pointer is returned if there is one, null otherwise.
 */
void * rdxtree_iter_next(struct rdxtree *tree, struct rdxtree_iter *iter);

#endif /* _KERN_RDXTREE_I_H */
