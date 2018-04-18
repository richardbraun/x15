/*
 * Copyright (c) 2012-2018 Richard Braun.
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
#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include <kern/atomic.h>
#include <kern/macros.h>
#include <kern/spinlock_types.h>
#include <kern/thread.h>
#include <machine/cpu.h>

/*
 * Uncontended lock values.
 *
 * Any other value implies a contended lock.
 */
#define SPINLOCK_UNLOCKED   0x0
#define SPINLOCK_LOCKED     0x1

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
    uint32_t prev;

    prev = atomic_cas(&lock->value, SPINLOCK_UNLOCKED,
                      SPINLOCK_LOCKED, ATOMIC_ACQUIRE);

    if (unlikely(prev != SPINLOCK_UNLOCKED)) {
        return EBUSY;
    }

    spinlock_own(lock);
    return 0;
}

void spinlock_lock_slow(struct spinlock *lock);

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
    spinlock_disown(lock);
    atomic_and(&lock->value, ~SPINLOCK_LOCKED, ATOMIC_RELEASE);
}

#endif /* KERN_SPINLOCK_I_H */
