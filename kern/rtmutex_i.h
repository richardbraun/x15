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
 */

#ifndef _KERN_RTMUTEX_I_H
#define _KERN_RTMUTEX_I_H

#include <stdbool.h>
#include <stdint.h>

#include <kern/assert.h>
#include <kern/atomic.h>
#include <kern/rtmutex_types.h>
#include <kern/thread.h>

/*
 * Real-time mutex flags.
 *
 * The "contended" flag indicates that threads are waiting for the mutex
 * to be unlocked. It forces threads trying to lock the mutex as well as
 * the owner to take the slow path.
 *
 * The "force-wait" flag prevents "stealing" a mutex. When a contended
 * mutex is unlocked, a thread may concurrently try to lock it. Without
 * this flag, it may succeed, and in doing so, it would prevent a
 * potentially higher priority thread from locking the mutex. The flag
 * forces all threads to not only take the slow path, but to also call
 * the turnstile wait function so that only the highest priority thread
 * may lock the mutex.
 */
#define RTMUTEX_CONTENDED   0x1
#define RTMUTEX_FORCE_WAIT  0x2

#define RTMUTEX_OWNER_MASK  (~((uintptr_t)(RTMUTEX_FORCE_WAIT \
                                           | RTMUTEX_CONTENDED)))

#define rtmutex_assert_owner_aligned(owner) \
    assert(((owner) & ~RTMUTEX_OWNER_MASK) == 0)

static inline uintptr_t
rtmutex_lock_fast(struct rtmutex *rtmutex)
{
    uintptr_t owner;

    owner = (uintptr_t)thread_self();
    rtmutex_assert_owner_aligned(owner);
    return atomic_cas_seq_cst(&rtmutex->owner, 0, owner);
}

static inline uintptr_t
rtmutex_unlock_fast(struct rtmutex *rtmutex)
{
    uintptr_t owner, prev_owner;

    owner = (uintptr_t)thread_self();
    rtmutex_assert_owner_aligned(owner);
    prev_owner = atomic_cas_seq_cst(&rtmutex->owner, owner, 0);
    assert((prev_owner & RTMUTEX_OWNER_MASK) == owner);
    return prev_owner;
}

void rtmutex_lock_slow(struct rtmutex *rtmutex);

void rtmutex_unlock_slow(struct rtmutex *rtmutex);

#endif /* _KERN_RTMUTEX_I_H */
