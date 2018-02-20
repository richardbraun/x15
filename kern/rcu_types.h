/*
 * Copyright (c) 2018 Richard Braun.
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

#ifndef _KERN_RCU_TYPES_H
#define _KERN_RCU_TYPES_H

#include <stdbool.h>

/*
 * Thread-local data used to track threads running read-side critical
 * sections.
 *
 * The window ID is valid if and only if the reader is linked.
 *
 * Interrupts and preemption must be disabled when accessing a reader.
 */
struct rcu_reader {
    unsigned int level;
    unsigned int wid;
    bool linked;
};

#endif /* _KERN_RCU_TYPES_H */
