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
 */

#ifndef KERN_SPINLOCK_I_H
#define KERN_SPINLOCK_I_H

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include <kern/atomic.h>
#include <kern/error.h>
#include <kern/macros.h>
#include <kern/spinlock_types.h>
#include <kern/thread.h>
#include <machine/cpu.h>

/*
 * Non-contended lock values.
 *
 * Any other lock value implies a contended lock.
 */
#define SPINLOCK_UNLOCKED   0
#define SPINLOCK_LOCKED     1

#ifdef CONFIG_SPINLOCK_DEBUG
#define SPINLOCK_TRACK_OWNER
#endif

#ifdef SPINLOCK_TRACK_OWNER

static inline void
spinlock_own(struct spinlock *lock)
{
    assert(!lock->owner);
    lock->owner = thread_self();
}

static inline void
spinlock_disown(struct spinlock *lock)
{
    assert(lock->owner == thread_self());
    lock->owner = NULL;
}

#else /* SPINLOCK_TRACK_OWNER */

#define spinlock_own(lock)
#define spinlock_disown(lock)

#endif /* SPINLOCK_TRACK_OWNER */

static inline int
spinlock_lock_fast(struct spinlock *lock)
{
    unsigned int prev;

    prev = atomic_cas_acquire(&lock->value, SPINLOCK_UNLOCKED, SPINLOCK_LOCKED);

    if (unlikely(prev != SPINLOCK_UNLOCKED)) {
        return ERROR_BUSY;
    }

    spinlock_own(lock);
    return 0;
}

static inline int
spinlock_unlock_fast(struct spinlock *lock)
{
    unsigned int prev;

    spinlock_disown(lock);
    prev = atomic_cas_release(&lock->value, SPINLOCK_LOCKED, SPINLOCK_UNLOCKED);

    if (unlikely(prev != SPINLOCK_LOCKED)) {
        return ERROR_BUSY;
    }

    return 0;
}

void spinlock_lock_slow(struct spinlock *lock);

void spinlock_unlock_slow(struct spinlock *lock);

static inline void
spinlock_lock_common(struct spinlock *lock)
{
    int error;

    error = spinlock_lock_fast(lock);

    if (unlikely(error)) {
        spinlock_lock_slow(lock);
    }
}

static inline void
spinlock_unlock_common(struct spinlock *lock)
{
    int error;

    error = spinlock_unlock_fast(lock);

    if (unlikely(error)) {
        spinlock_unlock_slow(lock);
    }
}

#endif /* KERN_SPINLOCK_I_H */
