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
 *
 *
 * Circular character buffer.
 */

#ifndef _KERN_CBUF_H
#define _KERN_CBUF_H

/*
 * Circular buffer descriptor.
 *
 * The buffer capacity must be a power-of-two. Indexes are absolute values
 * which can overflow. Their difference cannot exceed the capacity.
 */
struct cbuf {
    char *buf;
    unsigned long capacity;
    unsigned long start;
    unsigned long end;
};

static inline unsigned long
cbuf_capacity(const struct cbuf *cbuf)
{
    return cbuf->capacity;
}

static inline unsigned long
cbuf_start(const struct cbuf *cbuf)
{
    return cbuf->start;
}

static inline unsigned long
cbuf_end(const struct cbuf *cbuf)
{
    return cbuf->end;
}

static inline unsigned long
cbuf_size(const struct cbuf *cbuf)
{
    return cbuf->end - cbuf->start;
}

static inline void
cbuf_clear(struct cbuf *cbuf)
{
    cbuf->start = cbuf->end;
}

/*
 * Initialize a circular buffer.
 *
 * The descriptor is set to use the given buffer for storage. Capacity
 * must be a power-of-two.
 */
void cbuf_init(struct cbuf *cbuf, char *buf, unsigned long capacity);

/*
 * Append a byte to a circular buffer.
 *
 * The end index is incremented. If the buffer is full, the oldest byte
 * is overwritten and the start index is updated accordingly.
 */
void cbuf_push(struct cbuf *cbuf, char byte);

/*
 * Read a byte from a circular buffer.
 *
 * If the buffer is empty, ERROR_AGAIN is returned. Otherwise, the oldest
 * byte is stored at the bytep address, the start index is incremented,
 * and 0 is returned.
 */
int cbuf_pop(struct cbuf *cbuf, char *bytep);

/*
 * Read a byte at a specific location.
 *
 * If the given index is outside buffer boundaries, ERROR_INVAL is returned.
 * Otherwise the byte is stored at the bytep address and 0 is returned.
 * The buffer isn't changed by this operation.
 */
int cbuf_read(const struct cbuf *cbuf, unsigned long index, char *bytep);

#endif /* _KERN_CBUF_H */
