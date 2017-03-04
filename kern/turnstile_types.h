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
 * Isolated type definition used to avoid inclusion circular dependencies.
 */

#ifndef _KERN_TURNSTILE_TYPES_H
#define _KERN_TURNSTILE_TYPES_H

#include <kern/plist_types.h>
#include <kern/spinlock_types.h>

struct turnstile;
struct turnstile_waiter;

/*
 * Per-thread turnstile data.
 *
 * The turnstile member indicates whether this thread is in a turnstile,
 * and is only valid if the thread is not running.
 *
 * The waiter points to the structure a thread uses to queue itself on
 * a turnstile. It is used to access a sleeping thread from another
 * thread, e.g. on wake-ups or priority updates.
 *
 * The list of owned turnstiles is used by priority propagation to
 * determine the top priority among all waiters, which is stored in
 * the thread data so that turnstiles are quickly unlocked.
 *
 * Locking keys :
 * (b) bucket
 * (t) turnstile_td
 */
struct turnstile_td {
    struct spinlock lock;
    struct turnstile *turnstile;                /* (t)   */
    struct turnstile_waiter *waiter;            /* (b,t) */
    struct plist owned_turnstiles;              /* (t)   */
    unsigned int top_global_priority;           /* (t)   */
    unsigned char top_sched_policy;             /* (t)   */
    unsigned short top_priority;                /* (t)   */
};

#endif /* _KERN_TURNSTILE_TYPES_H */
