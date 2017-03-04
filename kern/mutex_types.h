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

#ifndef _KERN_MUTEX_TYPES_H
#define _KERN_MUTEX_TYPES_H

#ifdef X15_MUTEX_PI

#include <kern/rtmutex_types.h>

/*
 * Do not directly alias rtmutex to make sure they cannot be used
 * with condition variables by mistake.
 */
struct mutex {
    struct rtmutex rtmutex;
};

#else /* X15_MUTEX_PI */

struct mutex {
    unsigned int state;
};

#endif /* X15_MUTEX_PI */

#endif /* _KERN_MUTEX_TYPES_H */
