/*
 * Copyright (c) 2018 Richard Braun.
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
 * Read-Copy Update.
 *
 * This module provides a synchronization framework for read-only lockless
 * operations, best used on read-mostly data structures.
 *
 * To learn more about RCU, see "Is Parallel Programming Hard, And, If So,
 * What Can You Do About It ?" by Paul E. McKenney.
 *
 * A thorough discussion of RCU's requirements can be found at [1].
 * However, the memory model and terminology used in that document being
 * different from C11, the memory barrier guarantees are hereby translated
 * into memory ordering guarantees :
 *
 *  1. All read-side critical sections started before a grace period
 *     synchronize with all works deferred before the same grace period.
 *  2. All work deferrals done before a grace period synchronize with
 *     all read-side critical sections completed after the same grace period.
 *  3. All work deferrals done before a grace period synchronize with
 *     all works deferred before the same grace period.
 *
 * [1] https://www.kernel.org/doc/Documentation/RCU/Design/Requirements/Requirements.html.
 */

#ifndef KERN_RCU_H
#define KERN_RCU_H

#include <kern/atomic.h>
#include <kern/init.h>
#include <kern/latomic.h>
#include <kern/rcu_i.h>
#include <kern/rcu_types.h>
#include <kern/thread.h>
#include <kern/work.h>

/*
 * Thread-local RCU data.
 */
struct rcu_reader;

/*
 * Safely store a pointer.
 *
 * This macro enforces release ordering on the given pointer.
 */
#define rcu_store_ptr(ptr, value) atomic_store(&(ptr), value, ATOMIC_RELEASE)

/*
 * Safely load a pointer.
 *
 * This macro enforces consume ordering on the given pointer.
 */
#define rcu_load_ptr(ptr) atomic_load(&(ptr), ATOMIC_CONSUME)

/*
 * Read-side critical section functions.
 *
 * Critical sections are preemptible, may safely nest, and may safely
 * be used in interrupt context. It is not allowed to sleep inside a
 * read-side critical section. However, it is allowed to acquire locks
 * that don't sleep, such as spin locks.
 */

/*
 * Enter a read-side critical section.
 *
 * This is an intra-thread acquire operation.
 */
static inline void
rcu_read_enter(void)
{
    rcu_reader_inc(thread_rcu_reader(thread_self()));
    latomic_fence(LATOMIC_ACQ_REL);
}

/*
 * Leave a read-side critical section.
 *
 * This is an intra-thread release operation.
 */
static inline void
rcu_read_leave(void)
{
    latomic_fence(LATOMIC_ACQ_REL);
    rcu_reader_dec(thread_rcu_reader(thread_self()));
}

/*
 * Initialize an RCU reader.
 */
void rcu_reader_init(struct rcu_reader *reader);

/*
 * Report a context switch on the current processor.
 *
 * The argument is the RCU reader of the preempted thread.
 *
 * Interrupts and preemption must be disabled when calling this function.
 */
void rcu_report_context_switch(struct rcu_reader *reader);

/*
 * Report a periodic event on the current processor.
 *
 * Interrupts and preemption must be disabled when calling this function.
 */
void rcu_report_periodic_event(void);

/*
 * Defer a work until all existing read-side references are dropped,
 * without blocking.
 */
void rcu_defer(struct work *work);

/*
 * Wait for all existing read-side references to be dropped.
 *
 * This function sleeps, and may do so for a moderately long duration,
 * at least a few system timer ticks, sometimes a lot more.
 */
void rcu_wait(void);

/*
 * This init operation provides :
 *  - read-side critical sections usable
 */
INIT_OP_DECLARE(rcu_bootstrap);

#endif /* KERN_RCU_H */
