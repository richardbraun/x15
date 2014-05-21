/*
 * Copyright (c) 2014 Richard Braun.
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
 * Generic event counters.
 */

#ifndef _KERN_EVCNT_H
#define _KERN_EVCNT_H

#include <kern/list.h>

/*
 * Size of the buffer storing an event counter name.
 */
#define EVCNT_NAME_SIZE 32

/*
 * Event counter structure.
 *
 * Event counters are guaranteed to be 64-bits wide.
 */
struct evcnt {
    unsigned long long count;
    struct list node;
    char name[EVCNT_NAME_SIZE];
};

/*
 * Initialize the evcnt module.
 *
 * This module is initialized by architecture-specific code. It is normally
 * safe to call this function very early at boot time.
 */
void evcnt_setup(void);

/*
 * Register the given counter.
 */
void evcnt_register(struct evcnt *evcnt, const char *name);

/*
 * Increment the given counter.
 *
 * It is the responsibility of the caller to synchronize access to the
 * counter.
 */
static inline void
evcnt_inc(struct evcnt *evcnt)
{
    evcnt->count++;
}

/*
 * Obtain the current value of the given counter.
 *
 * Since counters are 64-bits wide, retrieving them on 32-bits systems might
 * return invalid values, although this should be very rare. As long as users
 * don't rely on them for critical operations, this is completely harmless.
 */
static inline unsigned long long
evcnt_read(const struct evcnt *evcnt)
{
    return evcnt->count;
}

/*
 * Display the registered event counters.
 *
 * A pattern can be used to filter the output. The result will only include
 * counters for which the beginning of their name matches the pattern.
 * If NULL, all counters are reported.
 */
void evcnt_info(const char *pattern);

#endif /* _KERN_EVCNT_H */
