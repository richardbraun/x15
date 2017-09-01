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

#include <kern/macros.h>
#include <kern/semaphore.h>
#include <kern/semaphore_i.h>
#include <kern/sleepq.h>

static int
semaphore_wait_slow_common(struct semaphore *semaphore,
                           bool timed, uint64_t ticks)
{
    struct sleepq *sleepq;
    unsigned long flags;
    unsigned int prev;
    int error;

    error = 0;

    sleepq = sleepq_lend(semaphore, false, &flags);

    for (;;) {
        prev = semaphore_dec(semaphore);

        if (prev != 0) {
            break;
        }

        if (!timed) {
            sleepq_wait(sleepq, "sem");
        } else {
            error = sleepq_timedwait(sleepq, "sem", ticks);

            if (error) {
                break;
            }
        }
    }

    sleepq_return(sleepq, flags);

    return error;
}

void
semaphore_wait_slow(struct semaphore *semaphore)
{
    __unused int error;

    error = semaphore_wait_slow_common(semaphore, false, 0);
    assert(!error);
}

int
semaphore_timedwait_slow(struct semaphore *semaphore, uint64_t ticks)
{
    return semaphore_wait_slow_common(semaphore, true, ticks);
}

void
semaphore_post_slow(struct semaphore *semaphore)
{
    struct sleepq *sleepq;
    unsigned long flags;

    sleepq = sleepq_acquire(semaphore, false, &flags);

    if (sleepq == NULL) {
        return;
    }

    sleepq_signal(sleepq);

    sleepq_release(sleepq, flags);
}
