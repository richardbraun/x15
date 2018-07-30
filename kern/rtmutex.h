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
 * Real-time mutual exclusion locks.
 *
 * A real-time mutex is similar to a regular mutex, except priority
 * inheritance is unconditionally enabled.
 */

#ifndef KERN_RTMUTEX_H
#define KERN_RTMUTEX_H

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>

#include <kern/atomic.h>
#include <kern/init.h>
#include <kern/macros.h>
#include <kern/rtmutex_i.h>
#include <kern/rtmutex_types.h>

struct rtmutex;

static inline bool
rtmutex_locked(const struct rtmutex *rtmutex)
{
    uintptr_t owner;

    owner = atomic_load(&rtmutex->owner, ATOMIC_RELAXED);
    return (owner != 0);
}

/*
 * Initialize a real-time mutex.
 */
static inline void
rtmutex_init(struct rtmutex *rtmutex)
{
    rtmutex->owner = 0;
}

/*
 * Attempt to lock the given real-time mutex.
 *
 * This function may not sleep.
 *
 * Return 0 on success, EBUSY if the mutex is already locked.
 */
static inline int
rtmutex_trylock(struct rtmutex *rtmutex)
{
    uintptr_t prev_owner;

    prev_owner = rtmutex_lock_fast(rtmutex);

    if (unlikely(prev_owner != 0)) {
        return EBUSY;
    }

    return 0;
}

/*
 * Lock a real-time mutex.
 *
 * If the mutex is already locked, the calling thread sleeps until the
 * mutex is unlocked, and its priority is propagated as needed to prevent
 * unbounded priority inversion.
 *
 * A mutex can only be locked once.
 *
 * This function may sleep.
 */
static inline void
rtmutex_lock(struct rtmutex *rtmutex)
{
    uintptr_t prev_owner;

    prev_owner = rtmutex_lock_fast(rtmutex);

    if (unlikely(prev_owner != 0)) {
        rtmutex_lock_slow(rtmutex);
    }
}

/*
 * Lock a real-time mutex, with a time boundary.
 *
 * The time boundary is an absolute time in ticks.
 *
 * If successful, the mutex is locked, otherwise an error is returned.
 * A mutex can only be locked once.
 *
 * This function may sleep.
 */
static inline int
rtmutex_timedlock(struct rtmutex *rtmutex, uint64_t ticks)
{
    uintptr_t prev_owner;

    prev_owner = rtmutex_lock_fast(rtmutex);

    if (unlikely(prev_owner != 0)) {
        return rtmutex_timedlock_slow(rtmutex, ticks);
    }

    return 0;
}

/*
 * Unlock a real-time mutex.
 *
 * The mutex must be locked, and must have been locked by the calling
 * thread.
 */
static inline void
rtmutex_unlock(struct rtmutex *rtmutex)
{
    uintptr_t prev_owner;

    prev_owner = rtmutex_unlock_fast(rtmutex);

    if (unlikely(prev_owner & RTMUTEX_CONTENDED)) {
        rtmutex_unlock_slow(rtmutex);
    }
}

/*
 * Mutex init operations. See kern/mutex.h.
 */
INIT_OP_DECLARE(rtmutex_bootstrap);
INIT_OP_DECLARE(rtmutex_setup);

#endif /* KERN_RTMUTEX_H */
