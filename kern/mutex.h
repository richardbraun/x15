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
 * Mutual exclusion locks.
 *
 * Unlike spin locks, acquiring a mutex may make the calling thread sleep.
 */

#ifndef _KERN_MUTEX_H
#define _KERN_MUTEX_H

#include <kern/list.h>
#include <kern/spinlock.h>

#define MUTEX_UNLOCKED  0
#define MUTEX_LOCKED    1
#define MUTEX_CONTENDED 2

struct mutex {
    unsigned long state;
    struct spinlock lock;
    struct list waiters;
};

#define MUTEX_INITIALIZER(mutex) \
    { MUTEX_UNLOCKED, SPINLOCK_INITIALIZER, LIST_INITIALIZER((mutex).waiters) }

void mutex_init(struct mutex *mutex);

/*
 * Return 0 on success, 1 if busy.
 */
int mutex_trylock(struct mutex *mutex);

void mutex_lock(struct mutex *mutex);

void mutex_unlock(struct mutex *mutex);

#endif /* _KERN_MUTEX_H */
