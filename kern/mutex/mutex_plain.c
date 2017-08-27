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
#include <kern/mutex.h>
#include <kern/mutex_types.h>
#include <kern/sleepq.h>

static int
mutex_plain_lock_slow_common(struct mutex *mutex, bool timed, uint64_t ticks)
{
    unsigned int state;
    struct sleepq *sleepq;
    unsigned long flags;
    int error;

    error = 0;

    sleepq = sleepq_lend(mutex, false, &flags);

    for (;;) {
        state = atomic_swap_release(&mutex->state, MUTEX_CONTENDED);

        if (state == MUTEX_UNLOCKED) {
            break;
        }

        if (!timed) {
            sleepq_wait(sleepq, "mutex");
        } else {
            error = sleepq_timedwait(sleepq, "mutex", ticks);

            if (error) {
                break;
            }
        }
    }

    if (error) {
        if (sleepq_empty(sleepq)) {
            atomic_cas(&mutex->state, MUTEX_CONTENDED,
                       MUTEX_LOCKED, ATOMIC_RELAXED);
        }

        goto out;
    }

    if (sleepq_empty(sleepq)) {
        atomic_store(&mutex->state, MUTEX_LOCKED, ATOMIC_RELAXED);
    }

out:
    sleepq_return(sleepq, flags);

    return error;
}

void
mutex_plain_lock_slow(struct mutex *mutex)
{
    int error;

    error = mutex_plain_lock_slow_common(mutex, false, 0);
    assert(!error);
}

int
mutex_plain_timedlock_slow(struct mutex *mutex, uint64_t ticks)
{
    return mutex_plain_lock_slow_common(mutex, true, ticks);
}

void
mutex_plain_unlock_slow(struct mutex *mutex)
{
    struct sleepq *sleepq;
    unsigned long flags;

    sleepq = sleepq_acquire(mutex, false, &flags);

    if (sleepq == NULL) {
        return;
    }

    sleepq_signal(sleepq);

    sleepq_release(sleepq, flags);
}
