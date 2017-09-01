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

/*
 * Locking keys :
 * (c) cpu_data
 * (a) atomic
 *
 * (*) The cpu member is used to determine which lock serializes access to
 * the structure. It must be accessed atomically, but updated while the
 * timer is locked.
 */
struct timer {
    union {
        struct hlist_node node; /* (c)      */
        struct work work;
    };

    uint64_t ticks;             /* (c)     */
    timer_fn_t fn;
    unsigned int cpu;           /* (c,a,*) */
    unsigned short state;       /* (c)     */
    unsigned short flags;       /* (c)     */
    struct thread *joiner;      /* (c)     */
};

#endif /* _KERN_TIMER_I_H */
