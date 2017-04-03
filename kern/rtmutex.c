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

#include <stddef.h>
#include <stdint.h>

#include <kern/assert.h>
#include <kern/atomic.h>
#include <kern/rtmutex.h>
#include <kern/rtmutex_i.h>
#include <kern/rtmutex_types.h>
#include <kern/thread.h>
#include <kern/turnstile.h>

static void
rtmutex_set_contended(struct rtmutex *rtmutex)
{
    atomic_or(&rtmutex->owner, RTMUTEX_CONTENDED, ATOMIC_SEQ_CST);
}

void
rtmutex_lock_slow(struct rtmutex *rtmutex)
{
    struct turnstile *turnstile;
    uintptr_t owner, prev_owner;
    struct thread *thread;
    uintptr_t bits;

    owner = (uintptr_t)thread_self();

    turnstile = turnstile_lend(rtmutex);

    rtmutex_set_contended(rtmutex);

    bits = RTMUTEX_CONTENDED;

    for (;;) {
        prev_owner = atomic_cas_seq_cst(&rtmutex->owner, bits, owner | bits);
        assert((prev_owner & bits) == bits);

        if (prev_owner == bits) {
            break;
        }

        thread = (struct thread *)(prev_owner & RTMUTEX_OWNER_MASK);
        turnstile_wait(turnstile, "rtmutex", thread);
        bits |= RTMUTEX_FORCE_WAIT;
    }

    turnstile_own(turnstile);

    if (turnstile_empty(turnstile)) {
        prev_owner = atomic_swap_seq_cst(&rtmutex->owner, owner);
        assert(prev_owner == (owner | bits));
    }

    turnstile_return(turnstile);

    /*
     * A lock owner should never perform priority propagation on itself,
     * because this process is done using its own priority, potentially
     * introducing unbounded priority inversion.
     * Instead, let new waiters do it, using their own priority.
     */
}

void
rtmutex_unlock_slow(struct rtmutex *rtmutex)
{
    struct turnstile *turnstile;
    uintptr_t owner, prev_owner;

    owner = (uintptr_t)thread_self();

    turnstile = turnstile_acquire(rtmutex);
    assert(turnstile != NULL);

    prev_owner = atomic_swap_seq_cst(&rtmutex->owner,
                                     RTMUTEX_FORCE_WAIT | RTMUTEX_CONTENDED);
    assert((prev_owner & RTMUTEX_OWNER_MASK) == owner);

    turnstile_disown(turnstile);
    turnstile_signal(turnstile);

    turnstile_release(turnstile);

    thread_propagate_priority();
}
