/*
 * Copyright (c) 2012 Richard Braun.
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
 * Spin lock.
 *
 * This implementation relies on the availability of hardware compare-and-swap
 * support.
 */

#ifndef _KERN_SPINLOCK_H
#define _KERN_SPINLOCK_H

#include <machine/atomic.h>
#include <machine/cpu.h>

struct spinlock {
    unsigned long locked;
};

/*
 * Static spin lock initializer.
 */
#define SPINLOCK_INITIALIZER { 0 }

/*
 * Initialize a spin lock.
 */
static inline void
spinlock_init(struct spinlock *lock)
{
    lock->locked = 0;
}

/*
 * Attempt to acquire a spin lock.
 *
 * Return false if acquired, true if busy.
 */
static inline int
spinlock_trylock(struct spinlock *lock)
{
    return atomic_cas(&lock->locked, 0, 1);
}

/*
 * Acquire a spin lock.
 */
static inline void
spinlock_lock(struct spinlock *lock)
{
    while (atomic_cas(&lock->locked, 0, 1))
        cpu_pause();
}

/*
 * Release a spin lock.
 */
static inline void
spinlock_unlock(struct spinlock *lock)
{
    atomic_swap(&lock->locked, 0);
}

#endif /* _KERN_SPINLOCK_H */
