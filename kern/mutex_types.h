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

#if defined(X15_USE_MUTEX_ADAPTIVE)
#include <kern/mutex/mutex_adaptive_types.h>
#elif defined(X15_USE_MUTEX_PI)
#include <kern/mutex/mutex_pi_types.h>
#elif defined(X15_USE_MUTEX_PLAIN)
#include <kern/mutex/mutex_plain_types.h>
#else
#error "unknown mutex implementation"
#endif

#endif /* _KERN_MUTEX_TYPES_H */
