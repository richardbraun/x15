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
 */

#include <kern/bitmap.h>
#include <kern/bitmap_i.h>
#include <kern/limits.h>

static inline unsigned long
bitmap_find_next_compute_complement(unsigned long word, int nr_bits)
{
    if (nr_bits < LONG_BIT)
        word |= (((unsigned long)-1) << nr_bits);

    return ~word;
}

int
bitmap_find_next_bit(const unsigned long *bm, int nr_bits, int bit,
                     int complement)
{
    const unsigned long *start, *end;
    unsigned long word;

    start = bm;
    end = bm + BITMAP_LONGS(nr_bits);

    if (bit >= LONG_BIT) {
        bitmap_lookup(bm, bit);
        nr_bits -= ((bm - start) * LONG_BIT);
    }

    word = *bm;

    if (complement)
        word = bitmap_find_next_compute_complement(word, nr_bits);

    if (bit < LONG_BIT)
        word &= ~(bitmap_mask(bit) - 1);

    for (;;) {
        bit = __builtin_ffsl(word);

        if (bit != 0)
            return ((bm - start) * LONG_BIT) + bit - 1;

        bm++;

        if (bm >= end)
            return -1;

        nr_bits -= LONG_BIT;
        word = *bm;

        if (complement)
            word = bitmap_find_next_compute_complement(word, nr_bits);
    }
}
