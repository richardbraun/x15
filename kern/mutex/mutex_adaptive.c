/*
 * Copyright (c) 2017 Agustina Arzille.
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
#include <kern/clock.h>
#include <kern/error.h>
#include <kern/init.h>
#include <kern/macros.h>
#include <kern/mutex.h>
#include <kern/mutex_types.h>
#include <kern/sleepq.h>
#include <kern/syscnt.h>
#include <kern/thread.h>
#include <machine/cpu.h>

#ifndef MUTEX_ADAPTIVE_DEBUG
#define MUTEX_ADAPTIVE_DEBUG 0
#endif /* MUTEX_ADAPTIVE_DEBUG */

#if MUTEX_ADAPTIVE_DEBUG

enum {
    MUTEX_ADAPTIVE_SC_SPINS,
    MUTEX_ADAPTIVE_SC_WAIT_SUCCESSES,
    MUTEX_ADAPTIVE_SC_WAIT_ERRORS,
    MUTEX_ADAPTIVE_SC_DOWNGRADES,
    MUTEX_ADAPTIVE_SC_ERROR_DOWNGRADES,
    MUTEX_ADAPTIVE_SC_ERROR_CLEARCONT,
    MUTEX_ADAPTIVE_SC_ERROR_RESET,
    MUTEX_ADAPTIVE_SC_FAST_UNLOCKS,
    MUTEX_ADAPTIVE_SC_SLOW_UNLOCKS,
    MUTEX_ADAPTIVE_SC_EXTERNAL_UNLOCKS,
    MUTEX_ADAPTIVE_SC_SIGNALS,
    MUTEX_ADAPTIVE_NR_SCS
};

static struct syscnt mutex_adaptive_sc_array[MUTEX_ADAPTIVE_NR_SCS];

static void
mutex_adaptive_register_sc(unsigned int index, const char *name)
{
    assert(index < ARRAY_SIZE(mutex_adaptive_sc_array));
    syscnt_register(&mutex_adaptive_sc_array[index], name);
}

static void
mutex_adaptive_setup_debug(void)
{
    mutex_adaptive_register_sc(MUTEX_ADAPTIVE_SC_SPINS,
                               "mutex_adaptive_spins");
    mutex_adaptive_register_sc(MUTEX_ADAPTIVE_SC_WAIT_SUCCESSES,
                               "mutex_adaptive_wait_successes");
    mutex_adaptive_register_sc(MUTEX_ADAPTIVE_SC_WAIT_ERRORS,
                               "mutex_adaptive_wait_errors");
    mutex_adaptive_register_sc(MUTEX_ADAPTIVE_SC_DOWNGRADES,
                               "mutex_adaptive_downgrades");
    mutex_adaptive_register_sc(MUTEX_ADAPTIVE_SC_ERROR_DOWNGRADES,
                               "mutex_adaptive_error_downgrades");
    mutex_adaptive_register_sc(MUTEX_ADAPTIVE_SC_ERROR_CLEARCONT,
                               "mutex_adaptive_error_clearcont");
    mutex_adaptive_register_sc(MUTEX_ADAPTIVE_SC_ERROR_RESET,
                               "mutex_adaptive_error_reset");
    mutex_adaptive_register_sc(MUTEX_ADAPTIVE_SC_FAST_UNLOCKS,
                               "mutex_adaptive_fast_unlocks");
    mutex_adaptive_register_sc(MUTEX_ADAPTIVE_SC_SLOW_UNLOCKS,
                               "mutex_adaptive_slow_unlocks");
    mutex_adaptive_register_sc(MUTEX_ADAPTIVE_SC_EXTERNAL_UNLOCKS,
                               "mutex_adaptive_external_unlocks");
    mutex_adaptive_register_sc(MUTEX_ADAPTIVE_SC_SIGNALS,
                               "mutex_adaptive_signals");
}

static void
mutex_adaptive_inc_sc(unsigned int index)
{
    assert(index < ARRAY_SIZE(mutex_adaptive_sc_array));
    syscnt_inc(&mutex_adaptive_sc_array[index]);
}

#else /* MUTEX_ADAPTIVE_DEBUG */
#define mutex_adaptive_setup_debug()
#define mutex_adaptive_inc_sc(x)
#endif /* MUTEX_ADAPTIVE_DEBUG */


static struct thread *
mutex_adaptive_get_thread(uintptr_t owner)
{
    return (struct thread *)(owner & ~MUTEX_ADAPTIVE_CONTENDED);
}

static void
mutex_adaptive_set_contended(struct mutex *mutex)
{
    atomic_or(&mutex->owner, MUTEX_ADAPTIVE_CONTENDED, ATOMIC_RELEASE);
}

static inline bool
mutex_adaptive_is_owner(struct mutex *mutex, uintptr_t owner)
{
    uintptr_t prev;

    prev = atomic_load(&mutex->owner, ATOMIC_RELAXED);
    return mutex_adaptive_get_thread(prev) == mutex_adaptive_get_thread(owner);
}

static int
mutex_adaptive_lock_slow_common(struct mutex *mutex, bool timed, uint64_t ticks)
{
    uintptr_t self, owner;
    struct sleepq *sleepq;
    struct thread *thread;
    unsigned long flags;
    int error;

    error = 0;
    self = (uintptr_t)thread_self();

    sleepq = sleepq_lend(mutex, false, &flags);

    mutex_adaptive_set_contended(mutex);

    do {
        owner = atomic_cas_acquire(&mutex->owner, MUTEX_ADAPTIVE_CONTENDED,
                                   self | MUTEX_ADAPTIVE_CONTENDED);
        assert(owner & MUTEX_ADAPTIVE_CONTENDED);

        if (mutex_adaptive_get_thread(owner) == NULL) {
            break;
        }

        /*
         * The owner may not return from the unlock function if a thread is
         * spinning on it.
         */
        while (mutex_adaptive_is_owner(mutex, owner)) {
            if (thread_is_running(mutex_adaptive_get_thread(owner))) {
                mutex_adaptive_inc_sc(MUTEX_ADAPTIVE_SC_SPINS);

                if (timed && clock_time_occurred(ticks, clock_get_time())) {
                    error = ERROR_TIMEDOUT;
                    break;
                }

                cpu_pause();
            } else {
                if (!timed) {
                    sleepq_wait(sleepq, "mutex");
                } else {
                    error = sleepq_timedwait(sleepq, "mutex", ticks);

                    if (error) {
                        break;
                    }
                }
            }
        }
    } while (!error);

    /*
     * Attempt to clear the contended bit.
     *
     * In case of success, the current thread becomes the new owner, and
     * simply checking if the sleep queue is empty is enough.
     *
     * Keep in mind accesses to the mutex word aren't synchronized by
     * the sleep queue, i.e. an unlock may occur completely concurrently
     * while attempting to clear the contended bit .
     */

    if (error) {
        mutex_adaptive_inc_sc(MUTEX_ADAPTIVE_SC_WAIT_ERRORS);

        if (sleepq_empty(sleepq)) {
            mutex_adaptive_inc_sc(MUTEX_ADAPTIVE_SC_ERROR_DOWNGRADES);
            owner = atomic_load(&mutex->owner, ATOMIC_RELAXED);
            assert(owner & MUTEX_ADAPTIVE_CONTENDED);
            thread = mutex_adaptive_get_thread(owner);

            /* If there is an owner, try to clear the contended bit */
            if (thread != NULL) {
                mutex_adaptive_inc_sc(MUTEX_ADAPTIVE_SC_ERROR_CLEARCONT);
                owner = atomic_cas(&mutex->owner, owner,
                                   (uintptr_t)thread, ATOMIC_RELAXED);
                assert(owner & MUTEX_ADAPTIVE_CONTENDED);
                thread = mutex_adaptive_get_thread(owner);
            }

            /*
             * If there is no owner, the previous owner is currently unlocking
             * the mutex, waiting for either a successful signal, or the
             * value of the mutex to become different from the contended bit.
             */
            if (thread == NULL) {
                mutex_adaptive_inc_sc(MUTEX_ADAPTIVE_SC_ERROR_RESET);
                owner = atomic_cas(&mutex->owner, owner, 0, ATOMIC_RELAXED);
                assert(owner == MUTEX_ADAPTIVE_CONTENDED);
            }
        }

        goto out;
    }

    mutex_adaptive_inc_sc(MUTEX_ADAPTIVE_SC_WAIT_SUCCESSES);

    if (sleepq_empty(sleepq)) {
        mutex_adaptive_inc_sc(MUTEX_ADAPTIVE_SC_DOWNGRADES);
        atomic_store(&mutex->owner, self, ATOMIC_RELAXED);
    }

out:
    sleepq_return(sleepq, flags);

    return error;
}

void
mutex_adaptive_lock_slow(struct mutex *mutex)
{
    __unused int error;

    error = mutex_adaptive_lock_slow_common(mutex, false, 0);
    assert(!error);
}

int
mutex_adaptive_timedlock_slow(struct mutex *mutex, uint64_t ticks)
{
    return mutex_adaptive_lock_slow_common(mutex, true, ticks);
}

void
mutex_adaptive_unlock_slow(struct mutex *mutex)
{
    uintptr_t self, owner;
    struct sleepq *sleepq;
    unsigned long flags;
    int error;

    self = (uintptr_t)thread_self() | MUTEX_ADAPTIVE_CONTENDED;

    for (;;) {
        owner = atomic_cas_release(&mutex->owner, self,
                                   MUTEX_ADAPTIVE_CONTENDED);

        if (owner == self) {
            break;
        } else {
            /*
             * The contended bit was cleared after the fast path failed,
             * but before the slow path (re)started.
             */
            assert(owner == (uintptr_t)thread_self());
            error = mutex_adaptive_unlock_fast(mutex);

            if (error) {
                continue;
            }

            mutex_adaptive_inc_sc(MUTEX_ADAPTIVE_SC_FAST_UNLOCKS);
            return;
        }
    }

    mutex_adaptive_inc_sc(MUTEX_ADAPTIVE_SC_SLOW_UNLOCKS);

    for (;;) {
        owner = atomic_load(&mutex->owner, ATOMIC_RELAXED);

        /*
         * This only happens if :
         *  1/ Another thread was able to become the new owner, in which
         *     case that thread isn't spinning on the current thread, i.e.
         *     there is no need for an additional reference.
         *  2/ A timeout cleared the contended bit.
         */
        if (owner != MUTEX_ADAPTIVE_CONTENDED) {
            mutex_adaptive_inc_sc(MUTEX_ADAPTIVE_SC_EXTERNAL_UNLOCKS);
            break;
        }

        /*
         * Avoid contending with incoming threads that are about to spin/wait
         * on the mutex. This is particularly expensive with queued locks.
         *
         * Also, this call returns NULL if another thread is currently spinning
         * on the current thread, in which case the latter doesn't return,
         * averting the need for an additional reference.
         */
        sleepq = sleepq_tryacquire(mutex, false, &flags);

        if (sleepq != NULL) {
            mutex_adaptive_inc_sc(MUTEX_ADAPTIVE_SC_SIGNALS);
            sleepq_signal(sleepq);
            sleepq_release(sleepq, flags);
            break;
        }

        /*
         * Acquiring the sleep queue may fail because of contention on
         * unrelated objects. Retry.
         */
    }
}

static int
mutex_adaptive_setup(void)
{
    mutex_adaptive_setup_debug();
    return 0;
}

INIT_OP_DEFINE(mutex_adaptive_setup,
#if MUTEX_ADAPTIVE_DEBUG
               INIT_OP_DEP(syscnt_setup, true),
#endif /* MUTEX_ADAPTIVE_DEBUG */
);
