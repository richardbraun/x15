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
 * Low resolution timer system.
 */

#ifndef _KERN_TIMER_H
#define _KERN_TIMER_H

#include <stdint.h>

#include <kern/init.h>

/*
 * Scheduling flags.
 */
#define TIMER_DETACHED      0x1     /* Timer completion isn't synchronized */
#define TIMER_INTR          0x2     /* Handler is run from interrupt context */
#define TIMER_HIGH_PRIO     0x4     /* Handler is run in high priority thread */

struct timer;

/*
 * Type for timer functions.
 */
typedef void (*timer_fn_t)(struct timer *);

#include <kern/timer_i.h>

/*
 * Return the absolute expiration time of the timer, in ticks.
 *
 * This function may not be called while another thread is scheduling the
 * timer.
 */
static inline uint64_t
timer_get_time(const struct timer *timer)
{
    return timer->ticks;
}

/*
 * Initialize a timer.
 *
 * Timers that are reponsible for releasing their own resources must
 * be detached.
 */
void timer_init(struct timer *timer, timer_fn_t fn, int flags);

/*
 * Schedule a timer.
 *
 * The time of expiration is an absolute time in ticks.
 *
 * Timers may safely be rescheduled after completion. Periodic timers are
 * implemented by rescheduling from the handler.
 *
 * If the timer has been canceled, this function does nothing. A
 * canceled timer must be reinitialized before being scheduled again.
 */
void timer_schedule(struct timer *timer, uint64_t ticks);

/*
 * Cancel a timer.
 *
 * The given timer must not be detached.
 *
 * If the timer has already expired, this function waits until the timer
 * function completes, or returns immediately if the function has already
 * completed.
 *
 * This function may safely be called from the timer handler, but not on
 * the current timer. Canceling a timer from the handler is achieved by
 * simply not rescheduling it.
 */
void timer_cancel(struct timer *timer);

/*
 * Report a periodic event on the current processor.
 *
 * Interrupts and preemption must be disabled when calling this function.
 */
void timer_report_periodic_event(void);

/*
 * This init operation provides :
 *  - timer initialization and scheduling
 *  - module fully initialized
 */
INIT_OP_DECLARE(timer_setup);

#endif /* _KERN_TIMER_H */
