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
 * Generic sleep queues.
 *
 * Sleep queues are used to build sleeping synchronization primitives
 * such as mutexes and condition variables.
 *
 * Although the sleep queues are mostly generic, this implementation
 * relies on knowing whether a synchronization object is a condition
 * variable or not, because waiting on a condition variable unlocks
 * the associated mutex, at which point two sleep queues are locked.
 * Handling condition variable sleep queues slightly differently
 * allows preventing deadlocks while keeping overall complexity low.
 *
 * In addition, despite being used to implement condition variables,
 * this implementation doesn't provide a broadcast call. The rationale
 * is to force users to implement "chained waking" in order to avoid
 * the thundering herd effect.
 */

#ifndef _KERN_SLEEPQ_H
#define _KERN_SLEEPQ_H

#include <stdbool.h>

struct sleepq;

/*
 * Early initialization of the sleepq module.
 *
 * This module is initialized by architecture-specific code. It should
 * be one of the first modules to be initialized since it's used by
 * synchronization objects that may be accessed very early.
 */
void sleepq_bootstrap(void);

/*
 * Initialize the sleepq module.
 */
void sleepq_setup(void);

/*
 * Create/destroy a sleep queue.
 */
struct sleepq * sleepq_create(void);
void sleepq_destroy(struct sleepq *sleepq);

/*
 * Acquire/release a sleep queue.
 *
 * Acquiring a sleep queue serializes all access and disables both
 * preemption and interrupts.
 *
 * The condition argument must be true if the synchronization object
 * is a condition variable.
 */
struct sleepq * sleepq_acquire(const void *sync_obj, bool condition,
                               unsigned long *flags);
void sleepq_release(struct sleepq *sleepq, unsigned long flags);

/*
 * Lend/return a sleep queue.
 *
 * A thread lends its private sleep queue to the sleepq module in
 * order to prepare its sleep. The sleep queue obtained on lending
 * is either the thread's queue, or an already existing queue for
 * this synchronization object if another thread is waiting.
 *
 * When multiple threads are waiting on the same queue, the extra
 * queues lent are kept in an internal free list, used when threads
 * are awaken to return a queue to them.
 *
 * Note that the sleep queue returned may not be the one lent.
 *
 * The sleep queue obtained when lending is automatically acquired.
 *
 * The condition argument must be true if the synchronization object
 * is a condition variable.
 */
struct sleepq * sleepq_lend(const void *sync_obj, bool condition,
                            unsigned long *flags);
void sleepq_return(struct sleepq *sleepq, unsigned long flags);

/*
 * Return true if the given sleep queue has no waiters.
 *
 * The sleep queue must be acquired when calling this function.
 */
bool sleepq_empty(const struct sleepq *sleepq);

/*
 * Wait for a wake up on the given sleep queue.
 *
 * The sleep queue must be lent when calling this function. It is
 * released and later reacquired before returning from this function.
 *
 * The calling thread is considered a waiter as long as it didn't
 * reacquire the sleep queue. This means that signalling a sleep queue
 * has no visible effect on the number of waiters until the queue is
 * released, e.g. if a single thread is waiting and another signals
 * the queue, the queue is not immediately considered empty.
 *
 * Threads are queued in FIFO order.
 */
void sleepq_wait(struct sleepq *sleepq, const char *wchan);

/*
 * Wake up a thread waiting on the given sleep queue, if any.
 *
 * The sleep queue must be acquired when calling this function.
 * A sleep queue may be signalled from interrupt context.
 *
 * Since a sleep queue must be lent (and in turn is automatically
 * acquired) when waiting, and acquired in order to signal it,
 * wake-ups are serialized and cannot be missed.
 *
 * Threads are queued in FIFO order, which means signalling a sleep
 * queue multiple times always awakens the same thread, regardless
 * of new waiters, as long as that first thread didn't reacquire the
 * sleep queue.
 */
void sleepq_signal(struct sleepq *sleepq);

#endif /* _KERN_SLEEPQ_H */
