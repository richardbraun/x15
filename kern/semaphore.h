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
 *
 *
 * Semaphores are resource-counting sleeping synchronization objects.
 * They are used to synchronize access to resources and signal events.
 *
 * The main operations supported by semaphores are locking and unlocking.
 * A semaphore is implemented as an atomic integer with an initial value.
 * Locking a semaphore means decrementing that integer, whereas unlocking
 * means incrementing it. Locking can only succeed if the semaphore value
 * is strictly greater than 0.
 *
 * Semaphores should not be used to implement critical sections. Instead,
 * use mutexes, which are similar to binary semaphores but with additional
 * restrictions that can improve debugging.
 */

#ifndef _KERN_SEMAPHORE_H
#define _KERN_SEMAPHORE_H

#include <kern/assert.h>
#include <kern/error.h>
#include <kern/macros.h>

#define SEMAPHORE_VALUE_MAX 32768

#include <kern/semaphore_i.h>

struct semaphore;

/*
 * Initialize a semaphore.
 */
static inline void
semaphore_init(struct semaphore *semaphore, unsigned int value)
{
    assert(value <= SEMAPHORE_VALUE_MAX);
    semaphore->value = value;
}

/*
 * Attempt to lock a semaphore.
 *
 * This function may not sleep.
 *
 * Return 0 on success, ERROR_AGAIN if the semaphore could not be decremented.
 */
static inline int
semaphore_trywait(struct semaphore *semaphore)
{
    unsigned int prev;

    prev = semaphore_dec(semaphore);

    if (prev == 0) {
        return ERROR_AGAIN;
    }

    return 0;
}

/*
 * Lock a semaphore.
 *
 * If the semaphore value doesn't allow locking, the calling thread sleeps
 * until the semaphore value is incremented.
 */
static inline void
semaphore_wait(struct semaphore *semaphore)
{
    unsigned int prev;

    prev = semaphore_dec(semaphore);

    if (prev != 0) {
        return;
    }

    semaphore_wait_slow(semaphore);
}

/*
 * Unlock a semaphore.
 *
 * If the semaphore value becomes strictly greater than 0, a thread waiting
 * on the semaphore is awaken.
 */
static inline void
semaphore_post(struct semaphore *semaphore)
{
    unsigned int prev;

    prev = semaphore_inc(semaphore);

    if (prev != 0) {
        return;
    }

    semaphore_post_slow(semaphore);
}

/*
 * Get the value of a semaphore.
 */
static inline unsigned int
semaphore_getvalue(const struct semaphore *semaphore)
{
    return read_once(semaphore->value);
}

#endif /* _KERN_SEMAPHORE_H */
