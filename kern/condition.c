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
 */

#include <kern/assert.h>
#include <kern/condition.h>
#include <kern/list.h>
#include <kern/mutex.h>
#include <kern/mutex_i.h>
#include <kern/spinlock.h>
#include <kern/stddef.h>
#include <kern/thread.h>

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
    struct mutex_waiter waiter;
    unsigned long state;

    waiter.thread = thread_self();

    spinlock_lock(&condition->lock);

    assert((condition->mutex == NULL) || (condition->mutex == mutex));

    if (condition->mutex == NULL)
        condition->mutex = mutex;

    list_insert_tail(&condition->waiters, &waiter.node);

    spinlock_lock(&mutex->lock);

    state = mutex_release(mutex);

    if (state == MUTEX_CONTENDED)
        mutex_signal(mutex);

    spinlock_unlock(&condition->lock);

    mutex_wait(mutex, &waiter);
    mutex_trydowngrade(mutex);

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

    mutex_queue(mutex, waiter);
    state = mutex_tryacquire_slow(mutex);

    if (state == MUTEX_UNLOCKED) {
        mutex_release(mutex);
        mutex_signal(mutex);
    }

    spinlock_unlock(&mutex->lock);
}

void
condition_broadcast(struct condition *condition)
{
    struct list waiters;
    struct mutex *mutex;
    unsigned long state;

    spinlock_lock(&condition->lock);

    if (condition->mutex == NULL) {
        spinlock_unlock(&condition->lock);
        return;
    }

    mutex = condition->mutex;
    condition->mutex = NULL;
    list_set_head(&waiters, &condition->waiters);
    list_init(&condition->waiters);

    spinlock_unlock(&condition->lock);

    spinlock_lock(&mutex->lock);

    mutex_queue_list(mutex, &waiters);
    state = mutex_tryacquire_slow(mutex);

    if (state == MUTEX_UNLOCKED) {
        mutex_release(mutex);
        mutex_signal(mutex);
    }

    spinlock_unlock(&mutex->lock);
}
