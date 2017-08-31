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
 * Timekeeping module.
 */

#ifndef _KERN_CLOCK_H
#define _KERN_CLOCK_H

#include <stdbool.h>
#include <stdint.h>

#include <kern/atomic.h>
#include <kern/clock_i.h>
#include <kern/init.h>
#include <kern/macros.h>

/*
 * Clock frequency.
 */
#define CLOCK_FREQ X15_CLOCK_FREQ

#if (CLOCK_FREQ < 100) || (CLOCK_FREQ > 1000) || (1000 % CLOCK_FREQ) != 0
#error "invalid clock frequency"
#endif /* (1000 % CLOCK_FREQ) != 0 */

/*
 * Arbitrary value used to determine if a time is in the past or the future.
 *
 * Time is represented as 64-bits unsigned integers counting ticks. The
 * global time currently starts from 0 but this isn't a strong assumption
 * users should rely on. Instead, all time checks involve a time reference
 * against which to compare. The result of that comparison, done by
 * substraction, is either in the future, i.e. the difference is less
 * than the expire threshold, or in the past, i.e. the difference is
 * greater (keep in mind the result is unsigned). The threshold must be
 * large enough to allow both a wide range of possible times in the future,
 * but also enough time in the past for reliable timeout detection. Note
 * that using signed integers would be equivalent to dividing the range
 * in two (almost) equal past and future halves.
 */
#define CLOCK_EXPIRE_THRESHOLD (-(1ULL << 60))

static inline uint64_t
clock_get_time(void)
{
    extern union clock_global_time clock_global_time;

#ifdef ATOMIC_HAVE_64B_OPS

    /*
     * Don't enforce a stronger memory order, since :
     *  1/ it's useless as long as the reader remains on the same processor
     *  2/ thread migration enforces sequential consistency
     */
    return atomic_load(&clock_global_time.ticks, ATOMIC_RELAXED);

#else /* ATOMIC_HAVE_64B_OPS */

    uint32_t high1, low, high2;

    /*
     * For machines with no 64-bits atomic accessors, this implementation uses
     * a variant of the two-digit monotonic-clock algorithm, described in the
     * paper "Concurrent Reading and Writing of Clocks" by Leslie Lamport.
     */

    do {
        high1 = atomic_load_acquire(&clock_global_time.high1);
        low = atomic_load_acquire(&clock_global_time.low);
        high2 = atomic_load(&clock_global_time.high2, ATOMIC_RELAXED);
    } while (high1 != high2);

    return ((uint64_t)high2 << 32) | low;

#endif /* ATOMIC_HAVE_64B_OPS */
}

static inline uint64_t
clock_ticks_to_ms(uint64_t ticks)
{
    return ticks * (1000 / CLOCK_FREQ);
}

static inline uint64_t
clock_ticks_from_ms(uint64_t ms)
{
    return DIV_CEIL(ms, (1000 / CLOCK_FREQ));
}

static inline bool
clock_time_expired(uint64_t t, uint64_t ref)
{
    return (t - ref) > CLOCK_EXPIRE_THRESHOLD;
}

static inline bool
clock_time_occurred(uint64_t t, uint64_t ref)
{
    return (t == ref) || clock_time_expired(t, ref);
}

void clock_tick_intr(void);

INIT_OP_DECLARE(clock_setup);

#endif /* _KERN_CLOCK_H */
