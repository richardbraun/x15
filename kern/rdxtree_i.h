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

#ifndef _KERN_RDXTREE_I_H
#define _KERN_RDXTREE_I_H

/*
 * Radix tree.
 */
struct rdxtree {
    unsigned short height;
    unsigned short flags;
    void *root;
};

/*
 * Radix tree iterator.
 *
 * The node member refers to the node containing the current pointer, if any.
 * The key member refers to the current pointer, and is valid if and only if
 * rdxtree_walk() has been called at least once on the iterator.
 */
struct rdxtree_iter {
    void *node;
    rdxtree_key_t key;
};

/*
 * Initialize an iterator.
 */
static inline void
rdxtree_iter_init(struct rdxtree_iter *iter)
{
    iter->node = NULL;
    iter->key = (rdxtree_key_t)-1;
}

int rdxtree_insert_common(struct rdxtree *tree, rdxtree_key_t key,
                          void *ptr, void ***slotp);

int rdxtree_insert_alloc_common(struct rdxtree *tree, void *ptr,
                                rdxtree_key_t *keyp, void ***slotp);

void * rdxtree_lookup_common(const struct rdxtree *tree, rdxtree_key_t key,
                             int get_slot);

void * rdxtree_walk(struct rdxtree *tree, struct rdxtree_iter *iter);

#endif /* _KERN_RDXTREE_I_H */
