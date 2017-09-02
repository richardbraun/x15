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
 */

#ifndef _KERN_MUTEX_H
#define _KERN_MUTEX_H

#include <stdint.h>

#if defined(X15_USE_MUTEX_ADAPTIVE)
#include <kern/mutex/mutex_adaptive_i.h>
#elif defined(X15_USE_MUTEX_PI)
#include <kern/mutex/mutex_pi_i.h>
#elif defined(X15_USE_MUTEX_PLAIN)
#include <kern/mutex/mutex_plain_i.h>
#else
#error "unknown mutex implementation"
#endif

#include <kern/init.h>
#include <kern/mutex_types.h>
#include <kern/thread.h>

/*
 * Initialize a mutex.
 */
static inline void
mutex_init(struct mutex *mutex)
{
    mutex_impl_init(mutex);
}

#define mutex_assert_locked(mutex) mutex_impl_assert_locked(mutex)

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
    return mutex_impl_trylock(mutex);
}

/*
 * Lock a mutex.
 *
 * On return, the mutex is locked. A mutex can only be locked once.
 *
 * This function may sleep.
 */
static inline void
mutex_lock(struct mutex *mutex)
{
    mutex_impl_lock(mutex);
}

/*
 * Lock a mutex, with a time boundary.
 *
 * The time boundary is an absolute time in ticks.
 *
 * If successful, the mutex is locked, otherwise an error is returned.
 * A mutex can only be locked once.
 *
 * This function may sleep.
 */
static inline int
mutex_timedlock(struct mutex *mutex, uint64_t ticks)
{
    return mutex_impl_timedlock(mutex, ticks);
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
    mutex_impl_unlock(mutex);

    /*
     * If this mutex was used along with a condition variable, wake up
     * a potential pending waiter.
     */
    thread_wakeup_last_cond();
}

/*
 * This init operation provides :
 *  - uncontended mutex locking
 *
 * Contended locking may only occur after starting the scheduler.
 */
INIT_OP_DECLARE(mutex_setup);

#endif /* _KERN_MUTEX_H */
