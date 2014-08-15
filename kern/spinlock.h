/*
 * Copyright (c) 2012-2014 Richard Braun.
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
 * Critical sections built with spin locks run with preemption disabled.
 */

#ifndef _KERN_SPINLOCK_H
#define _KERN_SPINLOCK_H

#include <kern/assert.h>
#include <kern/macros.h>
#include <kern/spinlock_i.h>
#include <kern/thread.h>
#include <kern/types.h>
#include <machine/cpu.h>

struct spinlock;

static inline void
spinlock_init(struct spinlock *lock)
{
    lock->locked = 0;
}

#define spinlock_assert_locked(lock) assert((lock)->locked)

/*
 * Return 0 on success, 1 if busy.
 */
static inline int
spinlock_trylock(struct spinlock *lock)
{
    int busy;

    thread_preempt_disable();
    busy = spinlock_tryacquire(lock);

    if (busy)
        thread_preempt_enable();

    return busy;
}

static inline void
spinlock_lock(struct spinlock *lock)
{
    thread_preempt_disable();
    spinlock_acquire(lock);
}

static inline void
spinlock_unlock(struct spinlock *lock)
{
    spinlock_release(lock);
    thread_preempt_enable();
}

/*
 * Versions of the spinlock functions that also disable interrupts during
 * critical sections.
 */

static inline int
spinlock_trylock_intr_save(struct spinlock *lock, unsigned long *flags)
{
    int busy;

    thread_preempt_disable();
    cpu_intr_save(flags);
    busy = spinlock_tryacquire(lock);

    if (busy) {
        cpu_intr_restore(*flags);
        thread_preempt_enable();
    }

    return busy;
}

static inline void
spinlock_lock_intr_save(struct spinlock *lock, unsigned long *flags)
{
    thread_preempt_disable();
    cpu_intr_save(flags);
    spinlock_acquire(lock);
}

static inline void
spinlock_unlock_intr_restore(struct spinlock *lock, unsigned long flags)
{
    spinlock_release(lock);
    cpu_intr_restore(flags);
    thread_preempt_enable();
}

#endif /* _KERN_SPINLOCK_H */
