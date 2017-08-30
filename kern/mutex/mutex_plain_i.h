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

#ifndef _KERN_MUTEX_PLAIN_I_H
#define _KERN_MUTEX_PLAIN_I_H

#ifndef _KERN_MUTEX_H
#error "don't include <kern/mutex/mutex_plain_i.h> directly," \
       " use <kern/mutex.h> instead"
#endif

#include <assert.h>
#include <stdint.h>

#include <kern/atomic.h>
#include <kern/error.h>
#include <kern/init.h>
#include <kern/mutex_types.h>

#define MUTEX_UNLOCKED  0
#define MUTEX_LOCKED    1
#define MUTEX_CONTENDED 2

static inline void
mutex_plain_init(struct mutex *mutex)
{
    mutex->state = MUTEX_UNLOCKED;
}

#define mutex_plain_assert_locked(mutex) \
    assert((mutex)->state != MUTEX_UNLOCKED)

static inline int
mutex_plain_lock_fast(struct mutex *mutex)
{
    unsigned int state;

    state = atomic_cas_acquire(&mutex->state, MUTEX_UNLOCKED, MUTEX_LOCKED);

    if (unlikely(state != MUTEX_UNLOCKED)) {
        return ERROR_BUSY;
    }

    return 0;
}

static inline int
mutex_plain_unlock_fast(struct mutex *mutex)
{
    unsigned int state;

    state = atomic_swap_release(&mutex->state, MUTEX_UNLOCKED);

    if (unlikely(state == MUTEX_CONTENDED)) {
        return ERROR_BUSY;
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
#define mutex_impl_assert_locked    mutex_plain_assert_locked

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

#define mutex_impl_setup mutex_plain_setup

INIT_OP_DECLARE(mutex_plain_setup);

#endif /* _KERN_MUTEX_PLAIN_I_H */
