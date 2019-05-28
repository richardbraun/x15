/*
 * Copyright (c) 2014-2019 Richard Braun.
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

#ifndef KERN_SREF_I_H
#define KERN_SREF_I_H

#include <stdint.h>

#include <kern/slist.h>
#include <kern/spinlock.h>
#include <kern/work.h>

#ifdef CONFIG_SREF_DEBUG
#define SREF_VERIFY
#endif

#define SREF_WEAKREF_DYING  ((uintptr_t)1)
#define SREF_WEAKREF_MASK   (~SREF_WEAKREF_DYING)

/*
 * Weak reference.
 *
 * A weak reference is a pointer to a reference counter in which the
 * least-significant bit is used to indicate whether the counter is
 * "dying", i.e. about to be destroyed.
 *
 * It must be accessed with atomic instructions. There is no need to
 * enforce memory order on access since the only data that depends on
 * the weak reference are cpu-local deltas.
 */
struct sref_weakref {
    uintptr_t addr;
};

/*
 * Counter flags.
 */
#define SREF_CNTF_QUEUED  0x1     /* Queued for review */
#define SREF_CNTF_DIRTY   0x2     /* Dirty zero seen */
#define SREF_CNTF_UNREF   0x4     /* Unreferenced, for debugging only */

/*
 * Scalable reference counter.
 *
 * It's tempting to merge the flags into the node member, but since they're
 * not protected by the same lock, store them separately.
 *
 * Locking keys :
 * (c) sref_counter
 * (g) sref_data
 *
 * Interrupts must be disabled when accessing a global counter.
 */
struct sref_counter {
    sref_noref_fn_t noref_fn;

#ifdef SREF_VERIFY
    struct {
#else /* SREF_VERIFY */
    union {
#endif /* SREF_VERIFY */
        struct {
            struct slist_node node;         /* (g) */
            struct spinlock lock;
            int flags;                      /* (c) */
            unsigned long value;            /* (c) */
            struct sref_weakref *weakref;
        };

        struct work work;
    };
};

#endif /* KERN_SREF_I_H */
