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

#include <kern/semaphore.h>
#include <kern/semaphore_i.h>
#include <kern/sleepq.h>

void
semaphore_wait_slow(struct semaphore *semaphore)
{
    struct sleepq *sleepq;
    unsigned long flags;
    unsigned int prev;

    sleepq = sleepq_lend(semaphore, false, &flags);

    for (;;) {
        prev = semaphore_dec(semaphore);

        if (prev != 0) {
            break;
        }

        sleepq_wait(sleepq, "sem");
    }

    sleepq_return(sleepq, flags);
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
