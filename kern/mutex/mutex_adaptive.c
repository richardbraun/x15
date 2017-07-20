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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <kern/atomic.h>
#include <kern/mutex.h>
#include <kern/mutex_types.h>
#include <kern/sleepq.h>
#include <kern/thread.h>
#include <machine/cpu.h>

static struct thread *
mutex_adaptive_get_thread(uintptr_t owner)
{
    return (struct thread *)(owner & ~MUTEX_ADAPTIVE_CONTENDED);
}

static void
mutex_adaptive_set_contended(struct mutex *mutex)
{
    atomic_or_acq_rel(&mutex->owner, MUTEX_ADAPTIVE_CONTENDED);
}

static inline bool
mutex_adaptive_is_owner(struct mutex *mutex, uintptr_t owner)
{
    uintptr_t prev;

    prev = atomic_load(&mutex->owner, ATOMIC_RELAXED);
    return mutex_adaptive_get_thread(prev) == mutex_adaptive_get_thread(owner);
}

void
mutex_adaptive_lock_slow(struct mutex *mutex)
{
    uintptr_t self, owner;
    struct sleepq *sleepq;
    unsigned long flags;

    self = (uintptr_t)thread_self();

    sleepq = sleepq_lend(mutex, false, &flags);

    mutex_adaptive_set_contended(mutex);

    for (;;) {
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
                cpu_pause();
            } else {
                sleepq_wait(sleepq, "mutex");
            }
        }
    }

    /*
     * A potentially spinning thread wouldn't be accounted in the sleep queue,
     * but the only potentially spinning thread is the new owner.
     */
    if (sleepq_empty(sleepq)) {
        atomic_store(&mutex->owner, self, ATOMIC_RELAXED);
    }

    sleepq_return(sleepq, flags);
}

void
mutex_adaptive_unlock_slow(struct mutex *mutex)
{
    uintptr_t owner;
    struct sleepq *sleepq;
    unsigned long flags;

    atomic_store(&mutex->owner, MUTEX_ADAPTIVE_CONTENDED, ATOMIC_RELEASE);

    for (;;) {
        owner = atomic_load(&mutex->owner, ATOMIC_RELAXED);

        /*
         * This only happens if another thread was able to become the new
         * owner, in which case that thread isn't spinning on the current
         * thread, i.e. there is no need for an additional reference.
         */
        if (owner != MUTEX_ADAPTIVE_CONTENDED) {
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
