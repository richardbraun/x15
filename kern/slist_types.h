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

#ifndef _KERN_SLIST_TYPES_H
#define _KERN_SLIST_TYPES_H

#include <stdbool.h>
#include <stddef.h>

#include "macros.h"

struct slist_node {
    struct slist_node *next;
};

struct slist {
    struct slist_node *first;
    struct slist_node *last;
};

#endif /* _KERN_SLIST_TYPES_H */
