/*
 * Copyright (c) 2017-2018 Richard Braun.
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

#include <assert.h>
#include <stdint.h>

#include <kern/bulletin.h>
#include <kern/list.h>
#include <kern/rcu.h>
#include <kern/spinlock.h>
#include <kern/thread.h>

static void
bulletin_sub_init(struct bulletin_sub *sub,
                  bulletin_notif_fn_t notif_fn, void *arg)
{
    sub->notif_fn = notif_fn;
    sub->arg = arg;
}

static void
bulletin_sub_notify(const struct bulletin_sub *sub, uintptr_t value)
{
    sub->notif_fn(value, sub->arg);
}

void
bulletin_init(struct bulletin *bulletin)
{
    spinlock_init(&bulletin->lock);
    list_init(&bulletin->subs);
}

void
bulletin_subscribe(struct bulletin *bulletin, struct bulletin_sub *sub,
                   bulletin_notif_fn_t notif_fn, void *arg)
{
    bulletin_sub_init(sub, notif_fn, arg);

    spinlock_lock(&bulletin->lock);
    list_rcu_insert_tail(&bulletin->subs, &sub->node);
    spinlock_unlock(&bulletin->lock);
}

void
bulletin_unsubscribe(struct bulletin *bulletin, struct bulletin_sub *sub)
{
    spinlock_lock(&bulletin->lock);
    list_rcu_remove(&sub->node);
    spinlock_unlock(&bulletin->lock);

    rcu_wait();
}

void
bulletin_publish(struct bulletin *bulletin, uintptr_t value)
{
    struct bulletin_sub *sub;

    assert(!thread_interrupted());

    rcu_read_enter();

    list_rcu_for_each_entry(&bulletin->subs, sub, node) {
        bulletin_sub_notify(sub, value);
    }

    rcu_read_leave();
}
