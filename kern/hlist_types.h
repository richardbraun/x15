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
 * Isolated type definition used to avoid inclusion circular dependencies.
 */

#ifndef _KERN_HLIST_TYPES_H
#define _KERN_HLIST_TYPES_H

/*
 * List node.
 *
 * The pprev member points to another node member instead of another node,
 * so that it may safely refer to the first member of the list head. Its
 * main purpose is to allow O(1) removal.
 */
struct hlist_node {
    struct hlist_node *next;
    struct hlist_node **pprev;
};

struct hlist {
    struct hlist_node *first;
};

#endif /* _KERN_HLIST_TYPES_H */
