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

#include <stdbool.h>
#include <stddef.h>

#include <kern/atomic.h>
#include <kern/mutex.h>
#include <kern/mutex_types.h>
#include <kern/sleepq.h>

void
mutex_plain_lock_slow(struct mutex *mutex)
{
    unsigned int state;
    struct sleepq *sleepq;
    unsigned long flags;

    sleepq = sleepq_lend(mutex, false, &flags);

    for (;;) {
        state = atomic_swap_release(&mutex->state, MUTEX_CONTENDED);

        if (state == MUTEX_UNLOCKED) {
            break;
        }

        sleepq_wait(sleepq, "mutex");
    }

    if (sleepq_empty(sleepq)) {
        atomic_store(&mutex->state, MUTEX_LOCKED, ATOMIC_RELAXED);
    }

    sleepq_return(sleepq, flags);
}

void
mutex_plain_unlock_slow(struct mutex *mutex)
{
    struct sleepq *sleepq;
    unsigned long flags;

    sleepq = sleepq_acquire(mutex, false, &flags);

    if (sleepq != NULL) {
        sleepq_signal(sleepq);
        sleepq_release(sleepq, flags);
    }
}
