/*
 * Copyright (c) 2013-2017 Richard Braun.
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
#include <kern/thread.h>

static int
condition_wait_common(struct condition *condition, struct mutex *mutex,
                      bool timed, uint64_t ticks)
{
    struct condition *last_cond;
    struct sleepq *sleepq;
    unsigned long flags;
    int error;

    mutex_assert_locked(mutex);

    /*
     * Special case :
     *
     * mutex_lock(lock);
     *
     * for (;;) {
     *     while (!done) {
     *         condition_wait(condition, lock);
     *     }
     *
     *     do_something();
     * }
     *
     * Pull the last condition before unlocking the mutex to prevent
     * mutex_unlock() from reacquiring the condition sleep queue.
     */
    last_cond = thread_pull_last_cond();

    sleepq = sleepq_lend(condition, true, &flags);

    mutex_unlock(mutex);

    if (last_cond != NULL) {
        assert(last_cond == condition);
        sleepq_wakeup(sleepq);
    }

    if (timed) {
        error = sleepq_timedwait(sleepq, "cond", ticks);
    } else {
        sleepq_wait(sleepq, "cond");
        error = 0;
    }

    if (!error) {
        thread_set_last_cond(condition);
    }

    sleepq_return(sleepq, flags);

    mutex_lock(mutex);

    return error;
}

void
condition_wait(struct condition *condition, struct mutex *mutex)
{
    __unused int error;

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
    unsigned long flags;

    sleepq = sleepq_acquire(condition, true, &flags);

    if (sleepq == NULL) {
        return;
    }

    sleepq_signal(sleepq);

    sleepq_release(sleepq, flags);
}

void
condition_broadcast(struct condition *condition)
{
    struct sleepq *sleepq;
    unsigned long flags;

    sleepq = sleepq_acquire(condition, true, &flags);

    if (sleepq == NULL) {
        return;
    }

    sleepq_broadcast(sleepq);

    sleepq_release(sleepq, flags);
}

void
condition_wakeup(struct condition *condition)
{
    struct sleepq *sleepq;
    unsigned long flags;

    sleepq = sleepq_acquire(condition, true, &flags);

    if (sleepq == NULL) {
        return;
    }

    sleepq_wakeup(sleepq);

    sleepq_release(sleepq, flags);
}
