/*
 * Copyright (c) 2014-2019 Richard Braun.
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
 * Scalable reference counting.
 *
 * The purpose of this module is to reduce the amount of inter-processor
 * communication usually involved with reference counting. Scalable
 * reference counters should only be used when multiprocessor scalability
 * is important because of the costs they imply (increased memory usage
 * and latencies).
 *
 * When a counter drops to 0, the no-reference function associated with it
 * is called in work context. As a result, special care must be taken if
 * using sref counters in the work module itself.
 */

#ifndef KERN_SREF_H
#define KERN_SREF_H

#include <kern/init.h>

/*
 * Scalable reference counter.
 */
struct sref_counter;

/*
 * Weak reference.
 */
struct sref_weakref;

/*
 * Type for no-reference functions.
 */
typedef void (*sref_noref_fn_t)(struct sref_counter *);

#include <kern/sref_i.h>

/*
 * Report a periodic event (normally the periodic timer interrupt) on the
 * current processor.
 *
 * Interrupts and preemption must be disabled when calling this function.
 */
void sref_report_periodic_event(void);

/*
 * Initialize a scalable reference counter.
 *
 * The no-reference function is called (from thread context) when it is
 * certain that the true number of references is 0.
 */
void sref_counter_init(struct sref_counter *counter,
                       unsigned long init_value,
                       struct sref_weakref *weakref,
                       sref_noref_fn_t noref_fn);

/*
 * Counter operations.
 *
 * These functions may safely be called in interrupt context.
 *
 * These functions imply a compiler barrier.
 */
void sref_counter_inc(struct sref_counter *counter);
void sref_counter_dec(struct sref_counter *counter);

/*
 * Attempt to get a reference from a weak reference.
 *
 * If successful, increment the reference counter before returning it.
 * Otherwise return NULL.
 *
 * This function may safely be called in interrupt context.
 */
struct sref_counter * sref_weakref_get(struct sref_weakref *weakref);

/*
 * This init operation provides :
 *  - sref counter and weakref initialization and usage
 */
INIT_OP_DECLARE(sref_bootstrap);

#endif /* KERN_SREF_H */
