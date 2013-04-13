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
 */

#include <kern/assert.h>
#include <kern/list.h>
#include <kern/mutex.h>
#include <kern/spinlock.h>
#include <kern/thread.h>
#include <machine/atomic.h>

void
mutex_init(struct mutex *mutex)
{
    mutex->state = MUTEX_UNLOCKED;
    spinlock_init(&mutex->lock);
    list_init(&mutex->waiters);
}

int
mutex_trylock(struct mutex *mutex)
{
    unsigned long state;

    state = atomic_cas(&mutex->state, MUTEX_UNLOCKED, MUTEX_LOCKED);

    if (state == MUTEX_UNLOCKED)
        return 0;

    return 1;
}

void
mutex_lock(struct mutex *mutex)
{
    struct mutex_waiter waiter;
    unsigned long state;

    state = atomic_cas(&mutex->state, MUTEX_UNLOCKED, MUTEX_LOCKED);

    if (state == MUTEX_UNLOCKED)
        return;

    /*
     * The mutex was either locked or contended. Unconditionnally update its
     * state to reflect it is now contended, and to check the previous state
     * while holding the waiters lock so that the current thread doesn't miss
     * a wakeup when the owner unlocks.
     */

    assert((state == MUTEX_LOCKED) || (state == MUTEX_CONTENDED));

    spinlock_lock(&mutex->lock);

    state = atomic_swap(&mutex->state, MUTEX_CONTENDED);

    if (state == MUTEX_UNLOCKED)
        goto out;

    waiter.thread = thread_self();
    list_insert_tail(&mutex->waiters, &waiter.node);

    do {
        thread_sleep(&mutex->lock);
        state = atomic_swap(&mutex->state, MUTEX_CONTENDED);
    } while (state != MUTEX_UNLOCKED);

    list_remove(&waiter.node);

out:
    if (list_empty(&mutex->waiters)) {
        state = atomic_swap(&mutex->state, MUTEX_LOCKED);
        assert(state == MUTEX_CONTENDED);
    }

    spinlock_unlock(&mutex->lock);
}

void
mutex_unlock(struct mutex *mutex)
{
    struct mutex_waiter *waiter;
    unsigned long state;

    state = atomic_swap(&mutex->state, MUTEX_UNLOCKED);

    if (state == MUTEX_LOCKED)
        return;

    /* The mutex was contended, wake up the next waiter if any */

    assert(state == MUTEX_CONTENDED);

    spinlock_lock(&mutex->lock);

    if (!list_empty(&mutex->waiters)) {
        waiter = list_first_entry(&mutex->waiters, struct mutex_waiter, node);
        thread_wakeup(waiter->thread);
    }

    spinlock_unlock(&mutex->lock);
}
