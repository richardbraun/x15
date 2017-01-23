/*
 * Copyright (c) 2012-2014 Richard Braun.
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

#ifndef _KERN_TYPES_H
#define _KERN_TYPES_H

#include <machine/types.h>

/*
 * Forward declarations.
 */
struct task;

/*
 * Types defined here to avoid inclusion loops.
 */

#include <kern/list.h>

struct spinlock {
    unsigned int locked;
};

struct mutex {
    unsigned int state;
    struct spinlock lock;
    struct list waiters;
};

struct condition {
    struct spinlock lock;
    struct mutex *mutex;
    struct list waiters;
};

#endif /* _KERN_TYPES_H */
