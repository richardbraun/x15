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

#include <assert.h>
#include <stddef.h>
#include <string.h>

#include <kern/cbuf.h>
#include <kern/error.h>
#include <kern/macros.h>

/* Negative close to 0 so that an overflow occurs early */
#define CBUF_INIT_INDEX ((size_t)-500)

void
cbuf_init(struct cbuf *cbuf, char *buf, size_t capacity)
{
    assert(ISP2(capacity));

    cbuf->buf = buf;
    cbuf->capacity = capacity;
    cbuf->start = CBUF_INIT_INDEX;
    cbuf->end = cbuf->start;
}

static size_t
cbuf_index(const struct cbuf *cbuf, size_t abs_index)
{
    return abs_index & (cbuf->capacity - 1);
}

static void
cbuf_update_start(struct cbuf *cbuf)
{
    /* Mind integer overflows */
    if (cbuf_size(cbuf) > cbuf->capacity) {
        cbuf->start = cbuf->end - cbuf->capacity;
    }
}

void
cbuf_push(struct cbuf *cbuf, char byte)
{
    cbuf->buf[cbuf_index(cbuf, cbuf->end)] = byte;
    cbuf->end++;
    cbuf_update_start(cbuf);
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
cbuf_write(struct cbuf *cbuf, size_t index, const void *buf, size_t size)
{
    char *start, *end, *buf_end;
    size_t new_end, skip;

    if ((cbuf->end - index) > cbuf_size(cbuf)) {
        return ERROR_INVAL;
    }

    new_end = index + size;

    if ((new_end - cbuf->start) > cbuf_size(cbuf)) {
        cbuf->end = new_end;

        if (size > cbuf_capacity(cbuf)) {
            skip = size - cbuf_capacity(cbuf);
            buf += skip;
            index += skip;
            size = cbuf_capacity(cbuf);
        }
    }

    start = &cbuf->buf[cbuf_index(cbuf, index)];
    end = start + size;
    buf_end = cbuf->buf + cbuf->capacity;

    if (end > buf_end) {
        skip = buf_end - start;
        memcpy(start, buf, skip);
        buf += skip;
        start = cbuf->buf;
        size -= skip;
    }

    memcpy(start, buf, size);
    cbuf_update_start(cbuf);
    return 0;
}

int
cbuf_read(const struct cbuf *cbuf, size_t index, void *buf, size_t *sizep)
{
    const char *start, *end, *buf_end;
    size_t size;

    size = cbuf->end - index;

    /* At least one byte must be available */
    if ((size - 1) >= cbuf_size(cbuf)) {
        return ERROR_INVAL;
    }

    if (*sizep > size) {
        *sizep = size;
    }

    start = &cbuf->buf[cbuf_index(cbuf, index)];
    end = start + *sizep;
    buf_end = cbuf->buf + cbuf->capacity;

    if (end <= buf_end) {
        size = *sizep;
    } else {
        size = buf_end - start;
        memcpy(buf, start, size);
        buf += size;
        start = cbuf->buf;
        size = *sizep - size;
    }

    memcpy(buf, start, size);
    return 0;
}
