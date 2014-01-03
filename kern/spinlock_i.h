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
 */

#ifndef _KERN_SPINLOCK_I_H
#define _KERN_SPINLOCK_I_H

#include <kern/assert.h>
#include <machine/atomic.h>
#include <machine/cpu.h>

struct spinlock {
    unsigned int locked;
};

/*
 * Return 0 on success, 1 if busy.
 */
static inline int
spinlock_tryacquire(struct spinlock *lock)
{
    return atomic_swap_uint(&lock->locked, 1);
}

static inline void
spinlock_acquire(struct spinlock *lock)
{
    while (spinlock_tryacquire(lock))
        cpu_pause();
}

static inline void
spinlock_release(struct spinlock *lock)
{
    unsigned int locked;

    locked = atomic_swap_uint(&lock->locked, 0);
    assert(locked);
}

#endif /* _KERN_SPINLOCK_I_H */
