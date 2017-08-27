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

#ifndef _KERN_TIMER_I_H
#define _KERN_TIMER_I_H

#include <stdbool.h>
#include <stdint.h>

#include <kern/hlist.h>
#include <kern/work.h>

struct timer {
    union {
        struct hlist_node node;
        struct work work;
    };

    uint64_t ticks;
    timer_fn_t fn;
    unsigned int cpu;
    unsigned short state;
    unsigned short flags;
    struct thread *joiner;
};

#endif /* _KERN_TIMER_I_H */
