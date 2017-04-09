/*
 * Copyright (c) 2012-2017 Richard Braun.
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
 * Spin locks.
 *
 * Critical sections built with spin locks run with preemption disabled.
 *
 * This module provides fair spin locks which guarantee time-bounded lock
 * acquisition depending only on the number of contending processors.
 */

#ifndef _KERN_SPINLOCK_H
#define _KERN_SPINLOCK_H

#include <kern/macros.h>
#include <kern/spinlock_i.h>
#include <kern/spinlock_types.h>
#include <kern/thread.h>
#include <machine/cpu.h>

struct spinlock;

#define spinlock_assert_locked(lock) assert((lock)->value != SPINLOCK_UNLOCKED)

/*
 * Initialize a spin lock.
 */
void spinlock_init(struct spinlock *lock);

/*
 * Attempt to lock the given spin lock.
 *
 * Return 0 on success, ERROR_BUSY if the spin lock is already locked.
 *
 * Preemption is disabled on success.
 */
static inline int
spinlock_trylock(struct spinlock *lock)
{
    int error;

    thread_preempt_disable();
    error = spinlock_lock_fast(lock);

    if (unlikely(error)) {
        thread_preempt_enable();
    }

    return error;
}

/*
 * Lock a spin lock.
 *
 * If the spin lock is already locked, the calling thread spins until the
 * spin lock is unlocked.
 *
 * A spin lock can only be locked once.
 *
 * This function disables preemption.
 */
static inline void
spinlock_lock(struct spinlock *lock)
{
    thread_preempt_disable();
    spinlock_lock_common(lock);
}

/*
 * Unlock a spin lock.
 *
 * The spin lock must be locked, and must have been locked on the same
 * processor it is unlocked on.
 *
 * This function may reenable preemption.
 */
static inline void
spinlock_unlock(struct spinlock *lock)
{
    spinlock_unlock_common(lock);
    thread_preempt_enable();
}

/*
 * Versions of the spinlock functions that also disable interrupts during
 * critical sections.
 */

/*
 * Attempt to lock the given spin lock.
 *
 * Return 0 on success, ERROR_BUSY if the spin lock is already locked.
 *
 * Preemption and interrupts are disabled on success, in which case the
 * flags passed by the caller are filled with the previous value of the
 * CPU flags.
 */
static inline int
spinlock_trylock_intr_save(struct spinlock *lock, unsigned long *flags)
{
    int error;

    thread_preempt_disable();
    cpu_intr_save(flags);
    error = spinlock_lock_fast(lock);

    if (unlikely(error)) {
        cpu_intr_restore(*flags);
        thread_preempt_enable();
    }

    return error;
}

/*
 * Lock a spin lock.
 *
 * If the spin lock is already locked, the calling thread spins until the
 * spin lock is unlocked.
 *
 * A spin lock can only be locked once.
 *
 * This function disables preemption and interrupts. The flags passed by
 * the caller are filled with the previous value of the CPU flags.
 */
static inline void
spinlock_lock_intr_save(struct spinlock *lock, unsigned long *flags)
{
    thread_preempt_disable();
    cpu_intr_save(flags);
    spinlock_lock_common(lock);
}

/*
 * Unlock a spin lock.
 *
 * The spin lock must be locked, and must have been locked on the same
 * processor it is unlocked on.
 *
 * This function may reenable preemption and interrupts, using the given
 * flags which must have been obtained with a lock or trylock operation.
 */
static inline void
spinlock_unlock_intr_restore(struct spinlock *lock, unsigned long flags)
{
    spinlock_unlock_common(lock);
    cpu_intr_restore(flags);
    thread_preempt_enable();
}

#endif /* _KERN_SPINLOCK_H */
