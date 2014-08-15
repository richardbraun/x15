/*
 * Copyright (c) 2013-2014 Richard Braun.
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
 * Mutual exclusion locks.
 *
 * Unlike spin locks, acquiring a mutex may make the calling thread sleep.
 */

#ifndef _KERN_MUTEX_H
#define _KERN_MUTEX_H

#include <kern/assert.h>
#include <kern/list.h>
#include <kern/mutex_i.h>
#include <kern/spinlock.h>
#include <kern/types.h>

struct mutex;

static inline void
mutex_init(struct mutex *mutex)
{
    mutex->state = MUTEX_UNLOCKED;
    spinlock_init(&mutex->lock);
    list_init(&mutex->waiters);
}

#define mutex_assert_locked(mutex) assert((mutex)->state != MUTEX_UNLOCKED)

/*
 * Return 0 on success, 1 if busy.
 */
static inline int
mutex_trylock(struct mutex *mutex)
{
    unsigned int state;

    state = mutex_tryacquire(mutex);

    if (state == MUTEX_UNLOCKED)
        return 0;

    return 1;
}

static inline void
mutex_lock(struct mutex *mutex)
{
    unsigned int state;

    state = mutex_tryacquire(mutex);

    if (state == MUTEX_UNLOCKED)
        return;

    assert((state == MUTEX_LOCKED) || (state == MUTEX_CONTENDED));

    mutex_lock_slow(mutex);
}

static inline void
mutex_unlock(struct mutex *mutex)
{
    unsigned int state;

    state = mutex_release(mutex);

    if (state == MUTEX_LOCKED)
        return;

    assert(state == MUTEX_CONTENDED);

    mutex_unlock_slow(mutex);
}

#endif /* _KERN_MUTEX_H */
