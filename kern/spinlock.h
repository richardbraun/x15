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
 * support. It also means that almost all spinlock operations imply a full
 * memory barrier. While this can be optimized by relying on architecture
 * specific properties, focus on correctness for the time being.
 */

#ifndef _KERN_SPINLOCK_H
#define _KERN_SPINLOCK_H

#include <kern/assert.h>
#include <kern/thread.h>
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

static inline void
spinlock_assert_locked(struct spinlock *lock)
{
    assert(lock->locked);
}

/*
 * Attempt to acquire a spin lock.
 *
 * Return true if acquired, false if busy.
 */
static inline int
spinlock_trylock(struct spinlock *lock)
{
    unsigned long busy;

    thread_preempt_disable();
    busy = atomic_cas(&lock->locked, 0, 1);

    if (!busy)
        return 1;

    thread_preempt_enable();
    return 0;
}

/*
 * Acquire a spin lock.
 */
static inline void
spinlock_lock(struct spinlock *lock)
{
    thread_preempt_disable();

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
    thread_preempt_enable();
}

#endif /* _KERN_SPINLOCK_H */
