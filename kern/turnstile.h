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
 * Priority propagation capable sleep queues.
 *
 * Turnstiles are used to build sleeping synchronization primitives where
 * ownership applies, such as mutexes. They allow threads with different
 * priorities to contend on the same synchronization object without
 * unbounded priority inversion.
 */

#ifndef _KERN_TURNSTILE_H
#define _KERN_TURNSTILE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <kern/init.h>
#include <kern/plist.h>
#include <kern/spinlock.h>
#include <kern/thread.h>
#include <kern/turnstile_types.h>

struct turnstile;

/*
 * Turnstile thread data.
 */
struct turnstile_td;

/*
 * Initialize turnstile thread data.
 */
static inline void
turnstile_td_init(struct turnstile_td *td)
{
    spinlock_init(&td->lock);
    td->turnstile = NULL;
    td->waiter = NULL;
    plist_init(&td->owned_turnstiles);
    td->top_global_priority = 0;
}

/*
 * Turnstile thread data locking functions.
 */

static inline bool
turnstile_td_locked(struct turnstile_td *td)
{
    return spinlock_locked(&(td)->lock);
}

static inline void
turnstile_td_lock(struct turnstile_td *td)
{
    spinlock_lock(&td->lock);
}

static inline int
turnstile_td_trylock(struct turnstile_td *td)
{
    return spinlock_trylock(&td->lock);
}

static inline void
turnstile_td_unlock(struct turnstile_td *td)
{
    spinlock_unlock(&td->lock);
}

/*
 * Functions managing the turnstile a thread is sleeping in.
 */

static inline void
turnstile_td_set_turnstile(struct turnstile_td *td,
                           struct turnstile *turnstile)
{
    td->turnstile = turnstile;
}

static inline struct turnstile *
turnstile_td_get_turnstile(const struct turnstile_td *td)
{
    return td->turnstile;
}

/*
 * Propagate priority starting at the thread containing the given thread data.
 */
void turnstile_td_propagate_priority(struct turnstile_td *td);

/*
 * Create/destroy a turnstile.
 */
struct turnstile * turnstile_create(void);
void turnstile_destroy(struct turnstile *turnstile);

/*
 * Acquire/release a turnstile.
 *
 * Acquiring a turnstile serializes all access and disables preemption.
 */
struct turnstile * turnstile_acquire(const void *sync_obj);
void turnstile_release(struct turnstile *turnstile);

/*
 * Lend/return a turnstile.
 *
 * A thread lends its private turnstile to the turnstile module in
 * order to prepare its sleep. The turnstile obtained on lending
 * is either the thread's turnstile, or an already existing turnstile
 * for this synchronization object if another thread is waiting.
 *
 * When multiple threads are waiting on the same turnstile, the extra
 * turnstiles lent are kept in an internal free list, used when threads
 * are awaken to return a turnstile to them.
 *
 * Note that the turnstile returned may not be the one lent.
 *
 * The turnstile obtained when lending is automatically acquired.
 */
struct turnstile * turnstile_lend(const void *sync_obj);
void turnstile_return(struct turnstile *turnstile);

/*
 * Return true if the given turnstile has no waiters.
 *
 * The turnstile must be acquired when calling this function.
 */
bool turnstile_empty(const struct turnstile *turnstile);

/*
 * Wait for a wake up on the given turnstile.
 *
 * The turnstile must be lent when calling this function. It is
 * released and later reacquired before returning from this function.
 *
 * The calling thread is considered a waiter as long as it didn't
 * reacquire the turnstile. This means that signalling a turnstile
 * has no visible effect on the number of waiters until the turnstile
 * is released, e.g. if a single thread is waiting and another signals
 * the turnstile, the turnstile is not immediately considered empty.
 *
 * If owner isn't NULL, it must refer to the thread currently owning
 * the associated synchronization object. The priority of the caller
 * is propagated to the chain of turnstiles and owners as necessary
 * to prevent unbounded priority inversion.
 *
 * When bounding the duration of the wait, the caller must pass an absolute
 * time in ticks, and ERROR_TIMEDOUT is returned if that time is reached
 * before the turnstile is signalled. In addition, if a timeout occurs,
 * the calling thread temporarily releases the turnstile before returning,
 * causing other threads to consider the turnstile as empty.
 */
void turnstile_wait(struct turnstile *turnstile, const char *wchan,
                    struct thread *owner);
int turnstile_timedwait(struct turnstile *turnstile, const char *wchan,
                        struct thread *owner, uint64_t ticks);

/*
 * Wake up a thread waiting on the given turnstile, if any.
 *
 * The turnstile must be acquired when calling this function.
 * Since a turnstile must be lent (and in turn is automatically
 * acquired) when waiting, and acquired in order to signal it,
 * wake-ups are serialized and cannot be missed.
 */
void turnstile_signal(struct turnstile *turnstile);

/*
 * Own/disown a turnstile.
 *
 * The turnstile must be lent when taking ownership, acquired when
 * releasing it.
 *
 * Ownership must be updated atomically with regard to the ownership
 * of the associated synchronization object.
 */
void turnstile_own(struct turnstile *turnstile);
void turnstile_disown(struct turnstile *turnstile);

/*
 * This init operation provides :
 *  - turnstile creation
 *  - module fully initialized
 */
INIT_OP_DECLARE(turnstile_setup);

#endif /* _KERN_TURNSTILE_H */
