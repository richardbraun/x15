/*
 * Copyright (c) 2013-2017 Richard Braun.
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

#ifndef _KERN_MUTEX_I_H
#define _KERN_MUTEX_I_H

#ifndef X15_MUTEX_PI

#include <kern/assert.h>
#include <kern/atomic.h>
#include <kern/mutex_types.h>

#define MUTEX_UNLOCKED  0
#define MUTEX_LOCKED    1
#define MUTEX_CONTENDED 2

static inline unsigned int
mutex_tryacquire(struct mutex *mutex)
{
    return atomic_cas_seq_cst(&mutex->state, MUTEX_UNLOCKED, MUTEX_LOCKED);
}

static inline unsigned int
mutex_release(struct mutex *mutex)
{
    unsigned int state;

    state = atomic_swap_seq_cst(&mutex->state, MUTEX_UNLOCKED);
    assert((state == MUTEX_LOCKED) || (state == MUTEX_CONTENDED));
    return state;
}

void mutex_lock_slow(struct mutex *mutex);

void mutex_unlock_slow(struct mutex *mutex);

#endif /* X15_MUTEX_PI */

#endif /* _KERN_MUTEX_I_H */
