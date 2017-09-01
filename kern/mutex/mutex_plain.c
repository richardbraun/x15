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
#include <kern/init.h>
#include <kern/macros.h>
#include <kern/mutex.h>
#include <kern/mutex_types.h>
#include <kern/sleepq.h>
#include <kern/syscnt.h>

#ifndef MUTEX_PLAIN_DEBUG
#define MUTEX_PLAIN_DEBUG 0
#endif /* MUTEX_PLAIN_DEBUG */

#if MUTEX_PLAIN_DEBUG

enum {
    MUTEX_PLAIN_SC_WAIT_SUCCESSES,
    MUTEX_PLAIN_SC_WAIT_ERRORS,
    MUTEX_PLAIN_SC_DOWNGRADES,
    MUTEX_PLAIN_SC_ERROR_DOWNGRADES,
    MUTEX_PLAIN_NR_SCS
};

static struct syscnt mutex_plain_sc_array[MUTEX_PLAIN_NR_SCS];

static void
mutex_plain_register_sc(unsigned int index, const char *name)
{
    assert(index < ARRAY_SIZE(mutex_plain_sc_array));
    syscnt_register(&mutex_plain_sc_array[index], name);
}

static void
mutex_plain_setup_debug(void)
{
    mutex_plain_register_sc(MUTEX_PLAIN_SC_WAIT_SUCCESSES,
                            "mutex_plain_wait_successes");
    mutex_plain_register_sc(MUTEX_PLAIN_SC_WAIT_ERRORS,
                            "mutex_plain_wait_errors");
    mutex_plain_register_sc(MUTEX_PLAIN_SC_DOWNGRADES,
                            "mutex_plain_downgrades");
    mutex_plain_register_sc(MUTEX_PLAIN_SC_ERROR_DOWNGRADES,
                            "mutex_plain_error_downgrades");
}

static void
mutex_plain_inc_sc(unsigned int index)
{
    assert(index < ARRAY_SIZE(mutex_plain_sc_array));
    syscnt_inc(&mutex_plain_sc_array[index]);
}

#else /* MUTEX_PLAIN_DEBUG */
#define mutex_plain_setup_debug()
#define mutex_plain_inc_sc(x)
#endif /* MUTEX_PLAIN_DEBUG */

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
        mutex_plain_inc_sc(MUTEX_PLAIN_SC_WAIT_ERRORS);

        if (sleepq_empty(sleepq)) {
            mutex_plain_inc_sc(MUTEX_PLAIN_SC_ERROR_DOWNGRADES);
            atomic_cas(&mutex->state, MUTEX_CONTENDED,
                       MUTEX_LOCKED, ATOMIC_RELAXED);
        }

        goto out;
    }

    mutex_plain_inc_sc(MUTEX_PLAIN_SC_WAIT_SUCCESSES);

    if (sleepq_empty(sleepq)) {
        mutex_plain_inc_sc(MUTEX_PLAIN_SC_DOWNGRADES);
        atomic_store(&mutex->state, MUTEX_LOCKED, ATOMIC_RELAXED);
    }

out:
    sleepq_return(sleepq, flags);

    return error;
}

void
mutex_plain_lock_slow(struct mutex *mutex)
{
    __unused int error;

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

static int
mutex_plain_setup(void)
{
    mutex_plain_setup_debug();
    return 0;
}

INIT_OP_DEFINE(mutex_plain_setup,
#if MUTEX_PLAIN_DEBUG
               INIT_OP_DEP(syscnt_setup, true),
#endif /* MUTEX_PLAIN_DEBUG */
);
