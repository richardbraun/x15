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

#include <stdbool.h>
#include <stddef.h>

#include <kern/assert.h>
#include <kern/condition.h>
#include <kern/condition_types.h>
#include <kern/mutex.h>
#include <kern/sleepq.h>
#include <kern/thread.h>

static void
condition_inc_nr_sleeping_waiters(struct condition *condition)
{
    condition->nr_sleeping_waiters++;
    assert(condition->nr_sleeping_waiters != 0);
}

static void
condition_dec_nr_sleeping_waiters(struct condition *condition)
{
    assert(condition->nr_sleeping_waiters != 0);
    condition->nr_sleeping_waiters--;
}

static void
condition_inc_nr_pending_waiters(struct condition *condition)
{
    condition->nr_pending_waiters++;
    assert(condition->nr_pending_waiters != 0);
}

static void
condition_dec_nr_pending_waiters(struct condition *condition)
{
    assert(condition->nr_pending_waiters != 0);
    condition->nr_pending_waiters--;
}

static void
condition_move_waiters(struct condition *condition)
{
    unsigned short old;

    assert(condition->nr_sleeping_waiters != 0);
    old = condition->nr_pending_waiters;
    condition->nr_pending_waiters += condition->nr_sleeping_waiters;
    assert(old < condition->nr_pending_waiters);
    condition->nr_sleeping_waiters = 0;
}

void
condition_wait(struct condition *condition, struct mutex *mutex)
{
    struct condition *last_cond;
    struct sleepq *sleepq;

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

    sleepq = sleepq_lend(condition, true);

    mutex_unlock(mutex);

    if (last_cond != NULL) {
        assert(last_cond == condition);

        if (condition->nr_pending_waiters != 0) {
            sleepq_signal(sleepq);
        }
    }

    condition_inc_nr_sleeping_waiters(condition);
    sleepq_wait(sleepq, "cond");
    condition_dec_nr_pending_waiters(condition);

    if (condition->nr_pending_waiters != 0) {
        thread_set_last_cond(condition);
    }

    sleepq_return(sleepq);

    mutex_lock(mutex);
}

void
condition_signal(struct condition *condition)
{
    struct sleepq *sleepq;

    sleepq = sleepq_acquire(condition, true);

    if (sleepq == NULL) {
        return;
    }

    if (condition->nr_sleeping_waiters == 0) {
        goto out;
    }

    sleepq_signal(sleepq);

    condition_dec_nr_sleeping_waiters(condition);
    condition_inc_nr_pending_waiters(condition);

out:
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

    if (condition->nr_sleeping_waiters == 0) {
        goto out;
    }

    sleepq_signal(sleepq);

    condition_move_waiters(condition);

out:
    sleepq_release(sleepq);
}

void
condition_wakeup(struct condition *condition)
{
    struct sleepq *sleepq;

    sleepq = sleepq_acquire(condition, true);

    if (sleepq == NULL) {
        return;
    }

    if (condition->nr_pending_waiters == 0) {
        goto out;
    }

    /*
     * Rely on the FIFO ordering of sleep queues so that signalling multiple
     * times always wakes up the same thread, as long as that thread didn't
     * reacquire the sleep queue.
     */
    sleepq_signal(sleepq);

out:
    sleepq_release(sleepq);
}
