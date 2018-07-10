/*
 * Copyright (c) 2013-2018 Richard Braun.
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
 * Locking order : mutex -> sleep queue
 */

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <kern/condition.h>
#include <kern/condition_types.h>
#include <kern/mutex.h>
#include <kern/sleepq.h>

static int
condition_wait_common(struct condition *condition, struct mutex *mutex,
                      bool timed, uint64_t ticks)
{
    struct sleepq *sleepq;
    int error;

    mutex_assert_locked(mutex);

    sleepq = sleepq_lend(condition, true);

    mutex_unlock(mutex);

    if (timed) {
        error = sleepq_timedwait(sleepq, "cond", ticks);
    } else {
        sleepq_wait(sleepq, "cond");
        error = 0;
    }

    sleepq_return(sleepq);

    mutex_lock(mutex);

    return error;
}

void
condition_wait(struct condition *condition, struct mutex *mutex)
{
    int error;

    error = condition_wait_common(condition, mutex, false, 0);
    assert(!error);
}

int
condition_timedwait(struct condition *condition,
                    struct mutex *mutex, uint64_t ticks)
{
    return condition_wait_common(condition, mutex, true, ticks);
}

void
condition_signal(struct condition *condition)
{
    struct sleepq *sleepq;

    sleepq = sleepq_acquire(condition, true);

    if (sleepq == NULL) {
        return;
    }

    sleepq_signal(sleepq);

    sleepq_release(sleepq);
}

void
condition_broadcast(struct condition *condition)
{
    struct sleepq *sleepq;

    sleepq = sleepq_acquire(condition, true);

    if (sleepq == NULL) {
        return;
    }

    sleepq_broadcast(sleepq);

    sleepq_release(sleepq);
}
