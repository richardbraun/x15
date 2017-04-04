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

#ifndef _KERN_SYSCNT_TYPES_H
#define _KERN_SYSCNT_TYPES_H

#include <stdint.h>

#include <kern/atomic.h>
#include <kern/list_types.h>
#include <kern/spinlock_types.h>

/*
 * Use atomic access on 64-bits systems, spinlock based critical sections
 * on 32-bits ones.
 */
struct syscnt {
#ifndef ATOMIC_HAVE_64B_OPS
    struct spinlock lock;
#endif /* __LP64__ */

    uint64_t value;
    struct list node;
    char name[SYSCNT_NAME_SIZE];
};

#endif /* _KERN_SYSCNT_TYPES_H */
