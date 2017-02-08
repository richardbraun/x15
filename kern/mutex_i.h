/*
 * Copyright (c) 2013-2014 Richard Braun.
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

#ifndef _KERN_MUTEX_I_H
#define _KERN_MUTEX_I_H

#include <kern/assert.h>
#include <kern/list.h>
#include <kern/mutex_types.h>
#include <kern/thread.h>
#include <machine/atomic.h>

#define MUTEX_UNLOCKED  0
#define MUTEX_LOCKED    1
#define MUTEX_CONTENDED 2

struct mutex_waiter {
    struct list node;
    struct thread *thread;
};

void mutex_lock_slow(struct mutex *mutex);

void mutex_unlock_slow(struct mutex *mutex);

static inline unsigned int
mutex_tryacquire(struct mutex *mutex)
{
    return atomic_cas_uint(&mutex->state, MUTEX_UNLOCKED, MUTEX_LOCKED);
}

static inline unsigned int
mutex_tryacquire_slow(struct mutex *mutex)
{
    return atomic_swap_uint(&mutex->state, MUTEX_CONTENDED);
}

static inline unsigned int
mutex_release(struct mutex *mutex)
{
    unsigned int state;

    state = atomic_swap_uint(&mutex->state, MUTEX_UNLOCKED);
    assert((state == MUTEX_LOCKED) || (state == MUTEX_CONTENDED));
    return state;
}

static inline void
mutex_queue(struct mutex *mutex, struct mutex_waiter *waiter)
{
    list_insert_tail(&mutex->waiters, &waiter->node);
}

static inline void
mutex_queue_list(struct mutex *mutex, struct list *waiters)
{
    list_concat(&mutex->waiters, waiters);
}

static inline void
mutex_wait(struct mutex *mutex, struct mutex_waiter *waiter)
{
    unsigned int state;

    do {
        thread_sleep(&mutex->lock, mutex, "mutex");
        state = mutex_tryacquire_slow(mutex);
    } while (state != MUTEX_UNLOCKED);

    list_remove(&waiter->node);
}

static inline void
mutex_signal(struct mutex *mutex)
{
    struct mutex_waiter *waiter;

    if (!list_empty(&mutex->waiters)) {
        waiter = list_first_entry(&mutex->waiters, struct mutex_waiter, node);
        thread_wakeup(waiter->thread);
    }
}

static inline void
mutex_trydowngrade(struct mutex *mutex)
{
    if (list_empty(&mutex->waiters)) {
        unsigned int state;

        state = atomic_swap_uint(&mutex->state, MUTEX_LOCKED);
        assert(state == MUTEX_CONTENDED);
    }
}

#endif /* _KERN_MUTEX_I_H */
