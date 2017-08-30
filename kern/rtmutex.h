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

#ifndef _KERN_RTMUTEX_H
#define _KERN_RTMUTEX_H

#include <assert.h>
#include <stdint.h>

#include <kern/error.h>
#include <kern/init.h>
#include <kern/macros.h>
#include <kern/rtmutex_i.h>
#include <kern/rtmutex_types.h>

struct rtmutex;

#define rtmutex_assert_locked(rtmutex) assert((rtmutex)->owner != 0)

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
 * Return 0 on success, ERROR_BUSY if the mutex is already locked.
 */
static inline int
rtmutex_trylock(struct rtmutex *rtmutex)
{
    uintptr_t prev_owner;

    prev_owner = rtmutex_lock_fast(rtmutex);

    if (unlikely(prev_owner != 0)) {
        return ERROR_BUSY;
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

INIT_OP_DECLARE(rtmutex_setup);

#endif /* _KERN_RTMUTEX_H */
