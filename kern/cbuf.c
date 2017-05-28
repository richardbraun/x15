/*
 * Copyright (c) 2015 Richard Braun.
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

#include <kern/assert.h>
#include <kern/cbuf.h>
#include <kern/error.h>
#include <kern/macros.h>

/* Negative close to 0 so that an overflow occurs early */
#define CBUF_INIT_INDEX ((unsigned long)-500)

void
cbuf_init(struct cbuf *cbuf, char *buf, unsigned long capacity)
{
    assert(ISP2(capacity));

    cbuf->buf = buf;
    cbuf->capacity = capacity;
    cbuf->start = CBUF_INIT_INDEX;
    cbuf->end = cbuf->start;
}

static unsigned long
cbuf_index(const struct cbuf *cbuf, unsigned long abs_index)
{
    return abs_index & (cbuf->capacity - 1);
}

void
cbuf_push(struct cbuf *cbuf, char byte)
{
    cbuf->buf[cbuf_index(cbuf, cbuf->end)] = byte;
    cbuf->end++;

    /* Mind integer overflows */
    if (cbuf_size(cbuf) > cbuf->capacity) {
        cbuf->start = cbuf->end - cbuf->capacity;
    }
}

int
cbuf_pop(struct cbuf *cbuf, char *bytep)
{
    if (cbuf_size(cbuf) == 0) {
        return ERROR_AGAIN;
    }

    *bytep = cbuf->buf[cbuf_index(cbuf, cbuf->start)];
    cbuf->start++;
    return 0;
}

int
cbuf_read(const struct cbuf *cbuf, unsigned long index, char *bytep)
{
    /* Mind integer overflows */
    if ((cbuf->end - index - 1) >= cbuf_size(cbuf)) {
        return ERROR_INVAL;
    }

    *bytep = cbuf->buf[cbuf_index(cbuf, index)];
    return 0;
}
