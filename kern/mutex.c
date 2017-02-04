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

#include <kern/mutex.h>
#include <kern/mutex_i.h>
#include <kern/spinlock.h>
#include <kern/thread.h>

void
mutex_lock_slow(struct mutex *mutex)
{
    struct mutex_waiter waiter;
    unsigned int state;

    spinlock_lock(&mutex->lock);

    state = mutex_tryacquire_slow(mutex);

    if (state != MUTEX_UNLOCKED) {
        waiter.thread = thread_self();
        mutex_queue(mutex, &waiter);
        mutex_wait(mutex, &waiter);
    }

    mutex_trydowngrade(mutex);

    spinlock_unlock(&mutex->lock);
}

void
mutex_unlock_slow(struct mutex *mutex)
{
    spinlock_lock(&mutex->lock);
    mutex_signal(mutex);
    spinlock_unlock(&mutex->lock);
}
