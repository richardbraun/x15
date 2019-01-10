/*
 * Copyright (c) 2017-2019 Richard Braun.
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
 * A semaphore is implemented as a counter with an initial value. Waiting
 * on a semaphore means decrementing that counter, whereas signalling
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

#include <kern/semaphore_i.h>

struct semaphore;

/*
 * Initialize a semaphore.
 */
void semaphore_init(struct semaphore *semaphore, uint16_t value,
                    uint16_t max_value);

/*
 * Attempt to decrement a semaphore.
 *
 * This function may not sleep.
 *
 * Return 0 on success, EAGAIN if the semaphore could not be decremented.
 */
int semaphore_trywait(struct semaphore *semaphore);

/*
 * Wait on a semaphore.
 *
 * If the semaphore value cannot be decremented, the calling thread sleeps
 * until the semaphore value is incremented.
 */
void semaphore_wait(struct semaphore *semaphore);

/*
 * Wait on a semaphore, with a time boundary.
 *
 * The time boundary is an absolute time in ticks.
 *
 * If successful, the semaphore is decremented, otherwise an error is returned.
 */
int semaphore_timedwait(struct semaphore *semaphore, uint64_t ticks);

/*
 * Signal a semaphore.
 *
 * This function attempts to increment the semaphore value. If successful, and
 * if one or more threads are waiting on the semaphore, one of them is awaken.
 *
 * A semaphore may safely be signalled from interrupt context.
 *
 * If successful, the semaphore is incremented. Otherwise, if the semaphore
 * value is already at its maximum before calling this function, EOVERFLOW
 * is returned.
 */
int semaphore_post(struct semaphore *semaphore);

#endif /* KERN_SEMAPHORE_H */
