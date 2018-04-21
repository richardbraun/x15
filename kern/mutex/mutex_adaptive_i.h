/*
 * Copyright (c) 2017 Agustina Arzille.
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

#ifndef KERN_MUTEX_ADAPTIVE_I_H
#define KERN_MUTEX_ADAPTIVE_I_H

#ifndef KERN_MUTEX_H
#error "don't include <kern/mutex/mutex_adaptive_i.h> directly," \
       " use <kern/mutex.h> instead"
#endif

#include <assert.h>
#include <errno.h>
#include <stdint.h>

#include <kern/atomic.h>
#include <kern/init.h>
#include <kern/macros.h>
#include <kern/mutex_types.h>
#include <kern/thread.h>

/*
 * Mutex flags.
 *
 * The "contended" flag indicates that threads are waiting for the mutex
 * to be unlocked, potentially spinning on the owner. It forces threads
 * trying to lock the mutex as well as the owner to take the slow path.
 */
#define MUTEX_ADAPTIVE_CONTENDED 0x1UL

static inline void
mutex_adaptive_init(struct mutex *mutex)
{
    mutex->owner = 0;
}

#define mutex_adaptive_assert_locked(mutex) assert((mutex)->owner != 0)

static inline int
mutex_adaptive_lock_fast(struct mutex *mutex)
{
    uintptr_t owner;

    owner = atomic_cas(&mutex->owner, 0,
                       (uintptr_t)thread_self(), ATOMIC_ACQUIRE);

    if (unlikely(owner != 0)) {
        return EBUSY;
    }

    return 0;
}

static inline int
mutex_adaptive_unlock_fast(struct mutex *mutex)
{
    uintptr_t owner;

    owner = atomic_cas(&mutex->owner, (uintptr_t)thread_self(),
                       0, ATOMIC_RELEASE);

    if (unlikely(owner & MUTEX_ADAPTIVE_CONTENDED)) {
        return EBUSY;
    }

    return 0;
}

void mutex_adaptive_lock_slow(struct mutex *mutex);
int mutex_adaptive_timedlock_slow(struct mutex *mutex, uint64_t ticks);
void mutex_adaptive_unlock_slow(struct mutex *mutex);

/*
 * Interface exported to the public mutex header.
 */

#define mutex_impl_init             mutex_adaptive_init
#define mutex_impl_assert_locked    mutex_adaptive_assert_locked

static inline int
mutex_impl_trylock(struct mutex *mutex)
{
    return mutex_adaptive_lock_fast(mutex);
}

static inline void
mutex_impl_lock(struct mutex *mutex)
{
    int error;

    error = mutex_adaptive_lock_fast(mutex);

    if (unlikely(error)) {
        mutex_adaptive_lock_slow(mutex);
    }
}

static inline int
mutex_impl_timedlock(struct mutex *mutex, uint64_t ticks)
{
    int error;

    error = mutex_adaptive_lock_fast(mutex);

    if (unlikely(error)) {
        error = mutex_adaptive_timedlock_slow(mutex, ticks);
    }

    return error;
}

static inline void
mutex_impl_unlock(struct mutex *mutex)
{
    int error;

    error = mutex_adaptive_unlock_fast(mutex);

    if (unlikely(error)) {
        mutex_adaptive_unlock_slow(mutex);
    }
}

/*
 * Mutex init operations. See kern/mutex.h.
 */

#define mutex_impl_bootstrap mutex_adaptive_bootstrap
INIT_OP_DECLARE(mutex_adaptive_bootstrap);

#define mutex_impl_setup mutex_adaptive_setup
INIT_OP_DECLARE(mutex_adaptive_setup);

#endif /* KERN_MUTEX_ADAPTIVE_I_H */
