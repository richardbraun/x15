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
 *
 *
 * Semaphores are resource-counting sleeping synchronization objects.
 * They are used to synchronize access to resources and signal events.
 *
 * The main operations supported by semaphores are waiting and signalling.
 * A semaphore is implemented as an atomic integer with an initial value.
 * Waiting on a semaphore means decrementing that integer, whereas signalling
 * means incrementing it. Waiting can only succeed if the semaphore value
 * is strictly greater than 0.
 *
 * The use of semaphores is generally discouraged. Mutexes are recommended
 * to implement preemptible critical sections, and spinlocks combined with
 * calls to thread_sleep() and thread_wakeup() are recommended for
 * non-preemptible critical sections. The reason is that a semaphore
 * internally already uses a spinlock, but that internal lock may not be
 * used to serialize access to anything else. This means that the only case
 * where a semaphore may be an efficient synchronization mechanism is
 * real-time signalling, e.g. an interrupt handler signalling a thread.
 * Here, "real-time" means that there is a guarantee that the thread has
 * always consumed the data produced by the interrupt handler before the
 * latter runs again.
 *
 * Since the kernel is an incomplete program without applications, it is
 * impossible to perform an analysis providing the real-time guarantee.
 * As a result, semaphores may only be used by application code.
 */

#ifndef KERN_SEMAPHORE_H
#define KERN_SEMAPHORE_H

#include <assert.h>
#include <errno.h>
#include <stdint.h>

#include <kern/atomic.h>

#define SEMAPHORE_VALUE_MAX 32768

#include <kern/semaphore_i.h>

struct semaphore;

/*
 * Initialize a semaphore.
 */
static inline void
semaphore_init(struct semaphore *semaphore, unsigned int value)
{
    assert(value <= SEMAPHORE_VALUE_MAX);
    semaphore->value = value;
}

/*
 * Attempt to decrement a semaphore.
 *
 * This function may not sleep.
 *
 * Return 0 on success, EAGAIN if the semaphore could not be decremented.
 */
static inline int
semaphore_trywait(struct semaphore *semaphore)
{
    unsigned int prev;

    prev = semaphore_dec(semaphore);

    if (prev == 0) {
        return EAGAIN;
    }

    return 0;
}

/*
 * Wait on a semaphore.
 *
 * If the semaphore value cannot be decremented, the calling thread sleeps
 * until the semaphore value is incremented.
 */
static inline void
semaphore_wait(struct semaphore *semaphore)
{
    unsigned int prev;

    prev = semaphore_dec(semaphore);

    if (prev == 0) {
        semaphore_wait_slow(semaphore);
    }
}

/*
 * Wait on a semaphore, with a time boundary.
 *
 * The time boundary is an absolute time in ticks.
 *
 * If successful, the semaphore is decremented, otherwise an error is returned.
 */
static inline int
semaphore_timedwait(struct semaphore *semaphore, uint64_t ticks)
{
    unsigned int prev;

    prev = semaphore_dec(semaphore);

    if (prev == 0) {
        return semaphore_timedwait_slow(semaphore, ticks);
    }

    return 0;
}

/*
 * Signal a semaphore.
 *
 * If the semaphore value becomes strictly greater than 0, a thread waiting
 * on the semaphore is awaken.
 *
 * A semaphore may be signalled from interrupt context.
 */
static inline void
semaphore_post(struct semaphore *semaphore)
{
    unsigned int prev;

    prev = semaphore_inc(semaphore);

    if (prev == 0) {
        semaphore_post_slow(semaphore);
    }
}

/*
 * Get the value of a semaphore.
 */
static inline unsigned int
semaphore_getvalue(const struct semaphore *semaphore)
{
    return atomic_load(&semaphore->value, ATOMIC_RELAXED);
}

#endif /* KERN_SEMAPHORE_H */
