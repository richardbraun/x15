/*
 * Copyright (c) 2013 Richard Braun.
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
 * In order to avoid the infamous thundering herd problem, this implementation
 * doesn't wake all threads when broadcasting a condition. Instead, they are
 * queued on the mutex associated with the condition, and an attempt to wake
 * one by locking and unlocking the mutex is performed. If the mutex is already
 * locked, the current owner does the same when unlocking.
 *
 * TODO Refactor mutex and condition code.
 */

#include <kern/assert.h>
#include <kern/condition.h>
#include <kern/list.h>
#include <kern/mutex.h>
#include <kern/spinlock.h>
#include <kern/stddef.h>
#include <kern/thread.h>
#include <machine/atomic.h>

void
condition_init(struct condition *condition)
{
    spinlock_init(&condition->lock);
    condition->mutex = NULL;
    list_init(&condition->waiters);
}

void
condition_wait(struct condition *condition, struct mutex *mutex)
{
    struct mutex_waiter waiter, *waiter_ptr;
    unsigned long state;

    waiter.thread = thread_self();

    spinlock_lock(&condition->lock);

    assert((condition->mutex == NULL) || (condition->mutex == mutex));

    if (condition->mutex == NULL)
        condition->mutex = mutex;

    list_insert_tail(&condition->waiters, &waiter.node);

    spinlock_lock(&mutex->lock);

    state = atomic_swap(&mutex->state, MUTEX_UNLOCKED);

    if (state != MUTEX_LOCKED) {
        assert(state == MUTEX_CONTENDED);

        if (!list_empty(&mutex->waiters)) {
            waiter_ptr = list_first_entry(&mutex->waiters, struct mutex_waiter,
                                          node);
            thread_wakeup(waiter_ptr->thread);
        }
    }

    spinlock_unlock(&condition->lock);

    do {
        thread_sleep(&mutex->lock);
        state = atomic_swap(&mutex->state, MUTEX_CONTENDED);
    } while (state != MUTEX_UNLOCKED);

    list_remove(&waiter.node);

    if (list_empty(&mutex->waiters)) {
        state = atomic_swap(&mutex->state, MUTEX_LOCKED);
        assert(state == MUTEX_CONTENDED);
    }

    spinlock_unlock(&mutex->lock);
}

void
condition_signal(struct condition *condition)
{
    struct mutex_waiter *waiter;
    struct mutex *mutex;
    unsigned long state;

    spinlock_lock(&condition->lock);

    if (condition->mutex == NULL) {
        spinlock_unlock(&condition->lock);
        return;
    }

    mutex = condition->mutex;
    waiter = list_first_entry(&condition->waiters, struct mutex_waiter, node);
    list_remove(&waiter->node);

    if (list_empty(&condition->waiters))
        condition->mutex = NULL;

    spinlock_unlock(&condition->lock);

    spinlock_lock(&mutex->lock);

    list_insert_tail(&mutex->waiters, &waiter->node);
    state = atomic_swap(&mutex->state, MUTEX_CONTENDED);

    if (state == MUTEX_UNLOCKED) {
        state = atomic_swap(&mutex->state, MUTEX_UNLOCKED);
        assert(state == MUTEX_CONTENDED);
        thread_wakeup(waiter->thread);
    }

    spinlock_unlock(&mutex->lock);
}

void
condition_broadcast(struct condition *condition)
{
    struct mutex_waiter *waiter;
    struct mutex *mutex;
    struct list tmp;
    unsigned long state;

    spinlock_lock(&condition->lock);

    if (condition->mutex == NULL) {
        spinlock_unlock(&condition->lock);
        return;
    }

    mutex = condition->mutex;
    condition->mutex = NULL;
    list_set_head(&tmp, &condition->waiters);
    list_init(&condition->waiters);

    spinlock_unlock(&condition->lock);

    spinlock_lock(&mutex->lock);

    list_concat(&mutex->waiters, &tmp);
    state = atomic_swap(&mutex->state, MUTEX_CONTENDED);

    if (state == MUTEX_UNLOCKED) {
        state = atomic_swap(&mutex->state, MUTEX_UNLOCKED);
        assert(state == MUTEX_CONTENDED);
        waiter = list_first_entry(&mutex->waiters, struct mutex_waiter, node);
        thread_wakeup(waiter->thread);
    }

    spinlock_unlock(&mutex->lock);
}
