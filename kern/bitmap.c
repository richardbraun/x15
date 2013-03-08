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
#include <kern/limits.h>

int
bitmap_find_next_bit(unsigned long *bm, int nr_bits, int bit, int complement)
{
    unsigned long word, *start, *end;

    start = bm;
    end = bm + BITMAP_LONGS(nr_bits);

    if (bit >= LONG_BIT)
        bitmap_lookup(&bm, &bit);

    word = *bm;

    if (complement)
        word = ~word;

    if (bit < LONG_BIT)
        word &= ~(bitmap_mask(bit) - 1);

    for (;;) {
        bit = __builtin_ffsl(word);

        if (bit != 0)
            return ((bm - start) * LONG_BIT) + bit - 1;

        bm++;

        if (bm >= end)
            return -1;

        word = *bm;

        if (complement)
            word = ~word;
    }
}
