/*
 * Copyright (c) 2017 Richard Braun.
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

#ifndef _KERN_SEMAPHORE_I_H
#define _KERN_SEMAPHORE_I_H

#include <kern/assert.h>
#include <kern/atomic.h>

struct semaphore {
    unsigned int value;
};

static inline unsigned int
semaphore_dec(struct semaphore *semaphore)
{
    unsigned int prev, value;

    do {
        value = semaphore->value;

        if (value == 0) {
            break;
        }

        prev = atomic_cas_acquire(&semaphore->value, value, value - 1);
    } while (prev != value);

    return value;
}

static inline unsigned int
semaphore_inc(struct semaphore *semaphore)
{
    unsigned int prev;

    prev = atomic_fetch_add(&semaphore->value, 1, ATOMIC_RELEASE);
    assert(prev != SEMAPHORE_VALUE_MAX);
    return prev;
}

void semaphore_wait_slow(struct semaphore *semaphore);

void semaphore_post_slow(struct semaphore *semaphore);

#endif /* _KERN_SEMAPHORE_I_H */
