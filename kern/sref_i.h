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
 */

#ifndef _KERN_SREF_I_H
#define _KERN_SREF_I_H

#include <kern/spinlock.h>
#include <kern/work.h>

#define SREF_QUEUED 0x1
#define SREF_DIRTY  0x2

/*
 * Scalable reference counter.
 *
 * It's tempting to merge the flags into the next member, but since they're
 * not protected by the same lock, store them separately.
 */
struct sref_counter {
    sref_noref_fn_t noref_fn;

    union {
        struct {
            struct sref_counter *next;
            struct spinlock lock;
            int flags;
            unsigned long value;
        };

        struct work work;
    };
};

#endif /* _KERN_SREF_I_H */
