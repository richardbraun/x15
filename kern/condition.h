/*
 * Copyright (c) 2013-2017 Richard Braun.
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
 * Condition variables.
 *
 * A condition variable is a synchronization primitive used to wait
 * until a predicate becomes true. Multiple threads can be waiting
 * for this condition. In order to synchronize changes on the predicate
 * with waiting and signalling, a condition variable must be associated
 * with a mutex.
 */

#ifndef _KERN_CONDITION_H
#define _KERN_CONDITION_H

#include <stdint.h>

#include <kern/condition_types.h>
#include <kern/mutex_types.h>

struct condition;

/*
 * Initialize a condition variable.
 */
#define condition_init(c) ((void)(c))

/*
 * Wait for a signal on the given condition variable.
 *
 * The associated mutex must be locked when calling this function.
 * It is unlocked before waiting and relocked before returning.
 *
 * When bounding the duration of the wait, the caller must pass an absolute
 * time in ticks, and ERROR_TIMEDOUT is returned if that time is reached
 * before the sleep queue is signalled.
 */
void condition_wait(struct condition *condition, struct mutex *mutex);
int condition_timedwait(struct condition *condition,
                        struct mutex *mutex, uint64_t ticks);

/*
 * Wake up one (signal) or all (broadcast) threads waiting on a
 * condition variable, if any.
 *
 * Although it is not necessary to hold the mutex associated to the
 * condition variable when calling these functions, doing so guarantees
 * that a wake-up done when changing the predicate cannot be missed by
 * waiting threads.
 */
void condition_signal(struct condition *condition);
void condition_broadcast(struct condition *condition);

/*
 * Wake up a pending thread.
 *
 * This function isn't part of the standard condition variable interface.
 * It is used to chain wake-ups to avoid the thundering herd effect.
 * When broadcasting a condition variable, a single thread is actually
 * awaken. Other threads become "pending waiters", still asleep but
 * eligible for wake-up when the mutex associated to the condition variable,
 * relocked when returning from condition_wait(), is finally unlocked.
 */
void condition_wakeup(struct condition *condition);

#endif /* _KERN_CONDITION_H */
