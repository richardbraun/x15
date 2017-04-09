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
 *
 *
 * Mutual exclusion sleep locks.
 *
 * Unlike spin locks, acquiring a mutex may make the calling thread sleep.
 *
 * TODO Adaptive spinning.
 */

#ifndef _KERN_MUTEX_H
#define _KERN_MUTEX_H

#include <kern/mutex_types.h>

#ifdef X15_MUTEX_PI

#include <kern/rtmutex.h>

struct mutex;

#define mutex_assert_locked(mutex) rtmutex_assert_locked(&(mutex)->rtmutex)

static inline void
mutex_init(struct mutex *mutex)
{
    rtmutex_init(&mutex->rtmutex);
}

static inline int
mutex_trylock(struct mutex *mutex)
{
    return rtmutex_trylock(&mutex->rtmutex);
}

static inline void
mutex_lock(struct mutex *mutex)
{
    rtmutex_lock(&mutex->rtmutex);
}

static inline void
mutex_unlock(struct mutex *mutex)
{
    rtmutex_unlock(&mutex->rtmutex);

    /*
     * If this mutex was used along with a condition variable, wake up
     * a potential pending waiter. This must be done after the mutex is
     * unlocked so that a higher priority thread can directly acquire it.
     */
    thread_wakeup_last_cond();
}

#else /* X15_MUTEX_PI */

#include <kern/assert.h>
#include <kern/error.h>
#include <kern/mutex_i.h>
#include <kern/thread.h>

struct mutex;

#define mutex_assert_locked(mutex) assert((mutex)->state != MUTEX_UNLOCKED)

/*
 * Initialize a mutex.
 */
static inline void
mutex_init(struct mutex *mutex)
{
    mutex->state = MUTEX_UNLOCKED;
}

/*
 * Attempt to lock the given mutex.
 *
 * This function may not sleep.
 *
 * Return 0 on success, ERROR_BUSY if the mutex is already locked.
 */
static inline int
mutex_trylock(struct mutex *mutex)
{
    unsigned int state;

    state = mutex_lock_fast(mutex);

    if (state == MUTEX_UNLOCKED) {
        return 0;
    }

    return ERROR_BUSY;
}

/*
 * Lock a mutex.
 *
 * If the mutex is already locked, the calling thread sleeps until the
 * mutex is unlocked.
 *
 * A mutex can only be locked once.
 */
static inline void
mutex_lock(struct mutex *mutex)
{
    unsigned int state;

    state = mutex_lock_fast(mutex);

    if (state == MUTEX_UNLOCKED) {
        return;
    }

    assert((state == MUTEX_LOCKED) || (state == MUTEX_CONTENDED));

    mutex_lock_slow(mutex);
}

/*
 * Unlock a mutex.
 *
 * The mutex must be locked, and must have been locked by the calling
 * thread.
 */
static inline void
mutex_unlock(struct mutex *mutex)
{
    unsigned int state;

    state = mutex_unlock_fast(mutex);

    if (state != MUTEX_LOCKED) {
        assert(state == MUTEX_CONTENDED);
        mutex_unlock_slow(mutex);
    }

    /*
     * If this mutex was used along with a condition variable, wake up
     * a potential pending waiter.
     */
    thread_wakeup_last_cond();
}

#endif /* X15_MUTEX_PI */

#endif /* _KERN_MUTEX_H */
