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

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <kern/atomic.h>
#include <kern/rtmutex.h>
#include <kern/rtmutex_i.h>
#include <kern/rtmutex_types.h>
#include <kern/thread.h>
#include <kern/turnstile.h>

static struct thread *
rtmutex_get_thread(uintptr_t owner)
{
    return (struct thread *)(owner & RTMUTEX_OWNER_MASK);
}

static void
rtmutex_set_contended(struct rtmutex *rtmutex)
{
    atomic_or(&rtmutex->owner, RTMUTEX_CONTENDED, ATOMIC_RELEASE);
}

static int
rtmutex_lock_slow_common(struct rtmutex *rtmutex, bool timed, uint64_t ticks)
{
    struct turnstile *turnstile;
    uintptr_t self, owner;
    struct thread *thread;
    uintptr_t bits;
    int error;

    error = 0;
    self = (uintptr_t)thread_self();

    turnstile = turnstile_lend(rtmutex);

    rtmutex_set_contended(rtmutex);

    bits = RTMUTEX_CONTENDED;

    for (;;) {
        owner = atomic_cas_acquire(&rtmutex->owner, bits, self | bits);
        assert((owner & bits) == bits);

        if (owner == bits) {
            break;
        }

        thread = rtmutex_get_thread(owner);

        if (!timed) {
            turnstile_wait(turnstile, "rtmutex", thread);
        } else {
            error = turnstile_timedwait(turnstile, "rtmutex", thread, ticks);

            if (error) {
                break;
            }
        }

        bits |= RTMUTEX_FORCE_WAIT;
    }

    if (error) {
        /*
         * Keep in mind more than one thread may have timed out on waiting.
         * These threads aren't considered waiters, making the turnstile
         * empty. The first to reacquire the turnstile clears the contention
         * bits, allowing the owner to unlock through the fast path.
         */
        if (turnstile_empty(turnstile)) {
            owner = atomic_load(&rtmutex->owner, ATOMIC_RELAXED);

            if (owner & RTMUTEX_CONTENDED) {
                owner &= RTMUTEX_OWNER_MASK;
                atomic_store(&rtmutex->owner, owner, ATOMIC_RELAXED);
            }
        }

        goto out;
    }

    turnstile_own(turnstile);

    if (turnstile_empty(turnstile)) {
        owner = atomic_swap(&rtmutex->owner, self, ATOMIC_RELAXED);
        assert(owner == (self | bits));
    }

out:
    turnstile_return(turnstile);

    /*
     * A lock owner should never perform priority propagation on itself,
     * because this process is done using its own priority, potentially
     * introducing unbounded priority inversion.
     * Instead, let new waiters do it, using their own priority.
     */

    return error;
}

void
rtmutex_lock_slow(struct rtmutex *rtmutex)
{
    int error;

    error = rtmutex_lock_slow_common(rtmutex, false, 0);
    assert(!error);
}

int
rtmutex_timedlock_slow(struct rtmutex *rtmutex, uint64_t ticks)
{
    return rtmutex_lock_slow_common(rtmutex, true, ticks);
}

void
rtmutex_unlock_slow(struct rtmutex *rtmutex)
{
    struct turnstile *turnstile;
    uintptr_t owner;

    for (;;) {
        turnstile = turnstile_acquire(rtmutex);

        if (turnstile != NULL) {
            break;
        }

        owner = rtmutex_unlock_fast(rtmutex);

        if (!(owner & RTMUTEX_CONTENDED)) {
            return;
        }
    }

    owner = atomic_swap_release(&rtmutex->owner,
                                RTMUTEX_FORCE_WAIT | RTMUTEX_CONTENDED);
    assert(rtmutex_get_thread(owner) == thread_self());

    turnstile_disown(turnstile);
    turnstile_signal(turnstile);

    turnstile_release(turnstile);

    /* TODO Make private, use thread_set_priority_propagation_needed instead */
    thread_propagate_priority();
}
