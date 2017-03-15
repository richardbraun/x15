/*
 * Copyright (c) 2014-2017 Richard Braun.
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
 * System counters.
 *
 * This module provides 64-bits general-purpose counters that can be
 * accessed and modified atomically from any context.
 */

#ifndef _KERN_SYSCNT_H
#define _KERN_SYSCNT_H

#include <stdint.h>

#include <kern/macros.h>
#include <kern/spinlock.h>
#include <machine/atomic.h>

/*
 * Size of the buffer storing a system counter name.
 */
#define SYSCNT_NAME_SIZE 32

#include <kern/syscnt_types.h>

/*
 * System counter.
 */
struct syscnt;

/*
 * Initialize the syscnt module.
 *
 * This module is initialized by architecture-specific code. It is normally
 * safe to call this function very early at boot time.
 */
void syscnt_setup(void);

/*
 * Initialize and register the given counter.
 *
 * The counter is set to 0.
 */
void syscnt_register(struct syscnt *syscnt, const char *name);

#ifdef __LP64__

static inline void
syscnt_add(struct syscnt *syscnt, int64_t delta)
{
    atomic_add_ulong(&syscnt->value, delta);
}

static inline uint64_t
syscnt_read(const struct syscnt *syscnt)
{
    return read_once(syscnt->value);
}

#else /* __LP64__ */

static inline void
syscnt_add(struct syscnt *syscnt, int64_t delta)
{
    unsigned long flags;

    spinlock_lock_intr_save(&syscnt->lock, &flags);
    syscnt->value += delta;
    spinlock_unlock_intr_restore(&syscnt->lock, flags);
}

static inline uint64_t
syscnt_read(struct syscnt *syscnt)
{
    unsigned long flags;
    uint64_t value;

    spinlock_lock_intr_save(&syscnt->lock, &flags);
    value = syscnt->value;
    spinlock_unlock_intr_restore(&syscnt->lock, flags);

    return value;
}

#endif /* __LP64__ */

static inline void
syscnt_inc(struct syscnt *syscnt)
{
    syscnt_add(syscnt, 1);
}

static inline void
syscnt_dec(struct syscnt *syscnt)
{
    syscnt_add(syscnt, -1);
}

/*
 * Display system counters.
 *
 * A prefix can be used to filter the output, where only counters with the
 * given prefix are displayed. If NULL, all counters are reported.
 */
void syscnt_info(const char *prefix);

#endif /* _KERN_SYSCNT_H */
