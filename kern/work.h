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
 * Deferred work queues.
 *
 * Works, like threads, are scheduled activities, but they are much shorter
 * and (usually) consume a lot less resources. They are allowed to block
 * and must run in thread context. This module provides thread pools to
 * concurrently handle queued works.
 */

#ifndef _KERN_WORK_H
#define _KERN_WORK_H

#include <kern/init.h>

/*
 * Work scheduling flags.
 */
#define WORK_HIGHPRIO   0x1 /* Use a high priority worker thread */

/*
 * Deferred work.
 *
 * This structure should be embedded in objects related to the work. It
 * stores the work function and is passed to it as its only parameter.
 * The function can then find the containing object with the structof macro.
 */
struct work;

/*
 * Queue of deferred works for batch scheduling.
 */
struct work_queue;

/*
 * Type for work functions.
 */
typedef void (*work_fn_t)(struct work *);

#include <kern/work_i.h>

static inline void
work_queue_init(struct work_queue *queue)
{
    queue->first = NULL;
    queue->last = NULL;
    queue->nr_works = 0;
}

static inline unsigned int
work_queue_nr_works(const struct work_queue *queue)
{
    return queue->nr_works;
}

static inline void
work_queue_push(struct work_queue *queue, struct work *work)
{
    work->next = NULL;

    if (queue->last == NULL) {
        queue->first = work;
    } else {
        queue->last->next = work;
    }

    queue->last = work;
    queue->nr_works++;
}

static inline struct work *
work_queue_pop(struct work_queue *queue)
{
    struct work *work;

    work = queue->first;
    queue->first = work->next;

    if (queue->last == work) {
        queue->last = NULL;
    }

    queue->nr_works--;
    return work;
}

static inline void
work_queue_transfer(struct work_queue *dest, struct work_queue *src)
{
    *dest = *src;
}

static inline void
work_queue_concat(struct work_queue *queue1, struct work_queue *queue2)
{
    if (queue2->nr_works == 0) {
        return;
    }

    if (queue1->nr_works == 0) {
        *queue1 = *queue2;
        return;
    }

    queue1->last->next = queue2->first;
    queue1->last = queue2->last;
    queue1->nr_works += queue2->nr_works;
}

static inline void
work_init(struct work *work, work_fn_t fn)
{
    work->fn = fn;
}

/*
 * Schedule work for deferred processing.
 *
 * This function may be called from interrupt context.
 */
void work_schedule(struct work *work, int flags);
void work_queue_schedule(struct work_queue *queue, int flags);

/*
 * Report a periodic event (normally the periodic timer interrupt) on the
 * current processor.
 *
 * Periodic events are used internally for optimizations.
 *
 * Interrupts and preemption must be disabled when calling this function.
 */
void work_report_periodic_event(void);

/*
 * This init operation provides :
 *  - works can be scheduled
 *  - module fully initialized
 */
INIT_OP_DECLARE(work_setup);

#endif /* _KERN_WORK_H */
