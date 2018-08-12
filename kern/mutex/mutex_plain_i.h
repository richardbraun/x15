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

#ifndef KERN_MUTEX_PLAIN_I_H
#define KERN_MUTEX_PLAIN_I_H

#ifndef KERN_MUTEX_H
#error "don't include <kern/mutex/mutex_plain_i.h> directly," \
       " use <kern/mutex.h> instead"
#endif

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>

#include <kern/atomic.h>
#include <kern/init.h>
#include <kern/mutex_types.h>

#define MUTEX_PLAIN_UNLOCKED    0
#define MUTEX_PLAIN_LOCKED      1
#define MUTEX_PLAIN_CONTENDED   2

static inline void
mutex_plain_init(struct mutex *mutex)
{
    mutex->state = MUTEX_PLAIN_UNLOCKED;
}

static inline bool
mutex_plain_locked(const struct mutex *mutex)
{
    unsigned int state;

    state = atomic_load(&mutex->state, ATOMIC_RELAXED);
    return (state != MUTEX_PLAIN_UNLOCKED);
}

static inline int
mutex_plain_lock_fast(struct mutex *mutex)
{
    unsigned int state;

    state = atomic_cas(&mutex->state, MUTEX_PLAIN_UNLOCKED,
                       MUTEX_PLAIN_LOCKED, ATOMIC_ACQUIRE);

    if (unlikely(state != MUTEX_PLAIN_UNLOCKED)) {
        return EBUSY;
    }

    return 0;
}

static inline int
mutex_plain_unlock_fast(struct mutex *mutex)
{
    unsigned int state;

    state = atomic_swap(&mutex->state, MUTEX_PLAIN_UNLOCKED, ATOMIC_RELEASE);

    if (unlikely(state == MUTEX_PLAIN_CONTENDED)) {
        return EBUSY;
    }

    return 0;
}

void mutex_plain_lock_slow(struct mutex *mutex);
int mutex_plain_timedlock_slow(struct mutex *mutex, uint64_t ticks);
void mutex_plain_unlock_slow(struct mutex *mutex);

/*
 * Interface exported to the public mutex header.
 */

#define mutex_impl_init             mutex_plain_init
#define mutex_impl_locked           mutex_plain_locked

static inline int
mutex_impl_trylock(struct mutex *mutex)
{
    return mutex_plain_lock_fast(mutex);
}

static inline void
mutex_impl_lock(struct mutex *mutex)
{
    int error;

    error = mutex_plain_lock_fast(mutex);

    if (unlikely(error)) {
        mutex_plain_lock_slow(mutex);
    }
}

static inline int
mutex_impl_timedlock(struct mutex *mutex, uint64_t ticks)
{
    int error;

    error = mutex_plain_lock_fast(mutex);

    if (unlikely(error)) {
        error = mutex_plain_timedlock_slow(mutex, ticks);
    }

    return error;
}

static inline void
mutex_impl_unlock(struct mutex *mutex)
{
    int error;

    error = mutex_plain_unlock_fast(mutex);

    if (unlikely(error)) {
        mutex_plain_unlock_slow(mutex);
    }
}

/*
 * Mutex init operations. See kern/mutex.h.
 */

#define mutex_impl_bootstrap mutex_plain_bootstrap
INIT_OP_DECLARE(mutex_plain_bootstrap);

#define mutex_impl_setup mutex_plain_setup
INIT_OP_DECLARE(mutex_plain_setup);

#endif /* KERN_MUTEX_PLAIN_I_H */
