/*
 * Copyright (c) 2013-2014 Richard Braun.
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
 */

#ifndef _KERN_CONDITION_H
#define _KERN_CONDITION_H

#include <stddef.h>

#include <kern/condition_types.h>
#include <kern/list.h>
#include <kern/spinlock.h>

/*
 * Condition variable.
 */
struct condition;

static inline void
condition_init(struct condition *condition)
{
    spinlock_init(&condition->lock);
    condition->mutex = NULL;
    list_init(&condition->waiters);
}

void condition_wait(struct condition *cond, struct mutex *mutex);

void condition_signal(struct condition *cond);

void condition_broadcast(struct condition *cond);

#endif /* _KERN_CONDITION_H */
