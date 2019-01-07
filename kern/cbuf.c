/*
 * Copyright (c) 2015-2018 Richard Braun.
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
 * Upstream site with license notes :
 * http://git.sceen.net/rbraun/librbraun.git/
 */

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <kern/cbuf.h>
#include <kern/macros.h>

/* Negative close to 0 so that an overflow occurs early */
#define CBUF_INIT_INDEX ((size_t)-500)

void
cbuf_init(struct cbuf *cbuf, void *buf, size_t capacity)
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
    if (cbuf_size(cbuf) > cbuf->capacity) {
        cbuf->start = cbuf->end - cbuf->capacity;
    }
}

static void
cbuf_update_end(struct cbuf *cbuf)
{
    if (cbuf_size(cbuf) > cbuf->capacity) {
        cbuf->end = cbuf->start + cbuf->capacity;
    }
}

int
cbuf_push(struct cbuf *cbuf, const void *buf, size_t size, bool erase)
{
    if (!erase) {
        size_t avail_size;

        avail_size = cbuf_avail_size(cbuf);

        if (size > avail_size) {
            return EAGAIN;
        }
    }

    return cbuf_write(cbuf, cbuf_end(cbuf), buf, size);
}

int
cbuf_pop(struct cbuf *cbuf, void *buf, size_t *sizep)
{
    int error;

    if (cbuf_size(cbuf) == 0) {
        return EAGAIN;
    }

    error = cbuf_read(cbuf, cbuf_start(cbuf), buf, sizep);
    assert(!error);
    cbuf->start += *sizep;
    return 0;
}

int
cbuf_pushb(struct cbuf *cbuf, uint8_t byte, bool erase)
{
    if (!erase) {
        size_t avail_size;

        avail_size = cbuf_avail_size(cbuf);

        if (avail_size == 0) {
            return EAGAIN;
        }
    }

    cbuf->buf[cbuf_index(cbuf, cbuf->end)] = byte;
    cbuf->end++;
    cbuf_update_start(cbuf);
    return 0;
}

int
cbuf_popb(struct cbuf *cbuf, void *bytep)
{
    uint8_t *ptr;

    if (cbuf_size(cbuf) == 0) {
        return EAGAIN;
    }

    ptr = bytep;

    if (ptr) {
        *ptr = cbuf->buf[cbuf_index(cbuf, cbuf->start)];
    }

    cbuf->start++;
    return 0;
}

int
cbuf_write(struct cbuf *cbuf, size_t index, const void *buf, size_t size)
{
    uint8_t *start, *end, *buf_end;
    size_t new_end, skip;

    if (!cbuf_index_valid(cbuf, index)) {
        return EINVAL;
    }

    new_end = index + size;

    if (!cbuf_index_valid(cbuf, new_end)) {
        cbuf->end = new_end;
        cbuf_update_start(cbuf);

        if (size > cbuf->capacity) {
            skip = size - cbuf->capacity;
            buf += skip;
            index += skip;
            size = cbuf->capacity;
        }
    }

    start = &cbuf->buf[cbuf_index(cbuf, index)];
    end = start + size;
    buf_end = cbuf->buf + cbuf->capacity;

    if ((end < cbuf->buf) || (end > buf_end)) {
        skip = buf_end - start;
        memcpy(start, buf, skip);
        buf += skip;
        start = cbuf->buf;
        size -= skip;
    }

    memcpy(start, buf, size);
    return 0;
}

int
cbuf_read(const struct cbuf *cbuf, size_t index, void *buf, size_t *sizep)
{
    const uint8_t *start, *end, *buf_end;
    size_t size;

    if (!cbuf_index_valid(cbuf, index)) {
        return EINVAL;
    }

    size = cbuf->end - index;

    if (*sizep > size) {
        *sizep = size;
    }

    start = &cbuf->buf[cbuf_index(cbuf, index)];
    end = start + *sizep;
    buf_end = cbuf->buf + cbuf->capacity;

    if ((end > cbuf->buf) && (end <= buf_end)) {
        size = *sizep;
    } else {
        size = buf_end - start;

        if (buf) {
            memcpy(buf, start, size);
            buf += size;
        }

        start = cbuf->buf;
        size = *sizep - size;
    }

    if (buf) {
        memcpy(buf, start, size);
    }

    return 0;
}

void
cbuf_set_start(struct cbuf *cbuf, size_t start)
{
    cbuf->start = start;
    cbuf_update_end(cbuf);
}

void
cbuf_set_end(struct cbuf *cbuf, size_t end)
{
    cbuf->end = end;
    cbuf_update_start(cbuf);
}
