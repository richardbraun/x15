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

#ifndef _KERN_MUTEX_PI_I_H
#define _KERN_MUTEX_PI_I_H

#ifndef _KERN_MUTEX_H
#error "don't include <kern/mutex/mutex_pi_i.h> directly," \
       " use <kern/mutex.h> instead"
#endif

#include <stdint.h>

#include <kern/mutex_types.h>
#include <kern/rtmutex.h>

/*
 * Interface exported to the public mutex header.
 */

static inline void
mutex_impl_init(struct mutex *mutex)
{
    rtmutex_init(&mutex->rtmutex);
}

#define mutex_impl_assert_locked(mutex) \
    rtmutex_assert_locked(&(mutex)->rtmutex)

static inline int
mutex_impl_trylock(struct mutex *mutex)
{
    return rtmutex_trylock(&mutex->rtmutex);
}

static inline void
mutex_impl_lock(struct mutex *mutex)
{
    rtmutex_lock(&mutex->rtmutex);
}

static inline int
mutex_impl_timedlock(struct mutex *mutex, uint64_t ticks)
{
    return rtmutex_timedlock(&mutex->rtmutex, ticks);
}

static inline void
mutex_impl_unlock(struct mutex *mutex)
{
    rtmutex_unlock(&mutex->rtmutex);
}

#define mutex_impl_setup rtmutex_setup

#endif /* _KERN_MUTEX_PI_I_H */
