/*
 * Copyright (c) 2018 Richard Braun.
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

#ifndef KERN_RCU_I_H
#define KERN_RCU_I_H

#include <assert.h>
#include <stdbool.h>

#include <kern/macros.h>
#include <kern/rcu_types.h>
#include <kern/thread.h>

void rcu_reader_leave(struct rcu_reader *reader);

static inline bool
rcu_reader_in_cs(const struct rcu_reader *reader)
{
    return reader->level != 0;
}

static inline bool
rcu_reader_linked(const struct rcu_reader *reader)
{
    assert(reader == thread_rcu_reader(thread_self()));
    return reader->linked;
}

static inline void
rcu_reader_inc(struct rcu_reader *reader)
{
    reader->level++;
    assert(reader->level != 0);
}

static inline void
rcu_reader_dec(struct rcu_reader *reader)
{
    assert(reader->level != 0);
    reader->level--;

    if (unlikely(!rcu_reader_in_cs(reader) && rcu_reader_linked(reader))) {
        rcu_reader_leave(reader);
    }
}

#endif /* KERN_RCU_I_H */
