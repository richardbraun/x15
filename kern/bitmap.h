/*
 * Copyright (c) 2013 Richard Braun.
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
 * Arbitrary-length bit arrays.
 *
 * Most functions do not check whether the given parameters are valid. This
 * is the responsibility of the caller.
 */

#ifndef _KERN_BITMAP_H
#define _KERN_BITMAP_H

#include <kern/limits.h>
#include <kern/macros.h>
#include <kern/string.h>
#include <machine/atomic.h>

#define BITMAP_LONGS(nr_bits) DIV_CEIL(nr_bits, LONG_BIT)

/*
 * Declare a bitmap.
 */
#define BITMAP_DECLARE(name, nr_bits) unsigned long name[BITMAP_LONGS(nr_bits)]

/*
 * Helper functions.
 */

/*
 * Adjust the bitmap pointer and the bit index so that the latter refers
 * to a bit inside the word pointed by the former.
 *
 * Implemented as a macro for const-correctness.
 */
#define bitmap_lookup(bm, bit)          \
MACRO_BEGIN                             \
    int i;                              \
                                        \
    i = BITMAP_LONGS((bit) + 1) - 1;    \
    (bm) += i;                          \
    (bit) -= i * LONG_BIT;              \
MACRO_END

static inline unsigned long
bitmap_mask(int bit)
{
    return (1UL << bit);
}

/*
 * Return the index of the next set bit in the bitmap, starting (and
 * including) the given bit index, or -1 if the bitmap is empty. If
 * complement is true, bits are toggled before searching so that the
 * result is the index of the next zero bit.
 */
int bitmap_find_next_bit(const unsigned long *bm, int nr_bits, int bit,
                         int complement);

/*
 * Public interface.
 */

static inline void
bitmap_zero(unsigned long *bm, int nr_bits)
{
    int n;

    n = BITMAP_LONGS(nr_bits);
    memset(bm, 0, n * sizeof(unsigned long));
}

static inline void
bitmap_fill(unsigned long *bm, int nr_bits)
{
    int n;

    n = BITMAP_LONGS(nr_bits);
    memset(bm, 0xff, n * sizeof(unsigned long));
}

static inline void
bitmap_set(unsigned long *bm, int bit)
{
    if (bit >= LONG_BIT)
        bitmap_lookup(bm, bit);

    *bm |= bitmap_mask(bit);
}

static inline void
bitmap_set_atomic(unsigned long *bm, int bit)
{
    if (bit >= LONG_BIT)
        bitmap_lookup(bm, bit);

    atomic_or(bm, bitmap_mask(bit));
}

static inline void
bitmap_clear(unsigned long *bm, int bit)
{
    if (bit >= LONG_BIT)
        bitmap_lookup(bm, bit);

    *bm &= ~bitmap_mask(bit);
}

static inline void
bitmap_clear_atomic(unsigned long *bm, int bit)
{
    if (bit >= LONG_BIT)
        bitmap_lookup(bm, bit);

    atomic_and(bm, ~bitmap_mask(bit));
}

static inline int
bitmap_test(const unsigned long *bm, int bit)
{
    if (bit >= LONG_BIT)
        bitmap_lookup(bm, bit);

    return ((*bm & bitmap_mask(bit)) != 0);
}

static inline int
bitmap_find_next(const unsigned long *bm, int nr_bits, int bit)
{
    return bitmap_find_next_bit(bm, nr_bits, bit, 0);
}

static inline int
bitmap_find_first(const unsigned long *bm, int nr_bits)
{
    return bitmap_find_next(bm, nr_bits, 0);
}

static inline int
bitmap_find_next_zero(const unsigned long *bm, int nr_bits, int bit)
{
    return bitmap_find_next_bit(bm, nr_bits, bit, 1);
}

static inline int
bitmap_find_first_zero(const unsigned long *bm, int nr_bits)
{
    return bitmap_find_next_zero(bm, nr_bits, 0);
}

#define bitmap_for_each(bm, nr_bits, bit)                       \
for ((bit) = 0;                                                 \
     ((bit) < nr_bits)                                          \
     && (((bit) = bitmap_find_next(bm, nr_bits, bit)) != -1);   \
     (bit)++)

#define bitmap_for_each_zero(bm, nr_bits, bit)                      \
for ((bit) = 0;                                                     \
     ((bit) < nr_bits)                                              \
     && (((bit) = bitmap_find_next_zero(bm, nr_bits, bit)) != -1);  \
     (bit)++)

#endif /* _KERN_BITMAP_H */
