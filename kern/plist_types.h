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

#ifndef _KERN_PLIST_TYPES_H
#define _KERN_PLIST_TYPES_H

#include <kern/list_types.h>

/*
 * The list member is used as the underlying regular linked list and
 * contains all entries, sorted by priority in ascending order. The
 * prio_list member contains exactly one entry for each priority
 * present, also sorted by priority in ascending order. An entry
 * on prio_list is the first entry in list for that priority.
 * Here is a representation of a possible priority list :
 *
 *      list--|1|--|3|--|3|--|3|--|4|--|6|--|6|--|8|
 *            | |  | |            | |  | |       |
 * prio_list--+ +--+ +------------+ +--+ +-------+
 *
 */
struct plist {
    struct list list;
    struct list prio_list;
};

struct plist_node {
    unsigned int priority;
    struct list node;
    struct list prio_node;
};

#endif /* _KERN_PLIST_TYPES_H */
