/*
 * Copyright (c) 2018-2019 Richard Braun.
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
 *
 *
 * FIFO message buffer.
 */

#ifndef KERN_MBUF_H
#define KERN_MBUF_H

#include <stdbool.h>
#include <stddef.h>

#include <kern/cbuf.h>

/*
 * Message buffer.
 *
 * Message buffers are built on top of circular byte buffers. They provide
 * discrete message transfer from a producer to a consumer.
 *
 * The order is computed from the maximum message size, and is used to
 * determine a header size that can represent up to 2^order - 1 bytes.
 */
struct mbuf {
    struct cbuf cbuf;
    size_t max_msg_size;
    unsigned int order;
};

static inline size_t
mbuf_start(const struct mbuf *mbuf)
{
    return cbuf_start(&mbuf->cbuf);
}

static inline size_t
mbuf_end(const struct mbuf *mbuf)
{
    return cbuf_end(&mbuf->cbuf);
}

/*
 * Initialize a message buffer.
 *
 * The descriptor is set to use the given buffer for storage. Capacity
 * must be a power-of-two.
 */
void mbuf_init(struct mbuf *mbuf, void *buf, size_t capacity,
               size_t max_msg_size);

/*
 * Clear a message buffer.
 */
void mbuf_clear(struct mbuf *mbuf);

/*
 * Push a message to a message buffer.
 *
 * If the message doesn't fit in the message buffer, either because it is
 * larger than the capacity, or because the function isn't allowed to erase
 * old messages and the message buffer doesn't have enough available memory
 * for the new message, EMSGSIZE is returned. If the message is larger than
 * the maximum message size, EINVAL is returned.
 */
int mbuf_push(struct mbuf *mbuf, const void *buf, size_t size, bool erase);

/*
 * Pop a message from a message buffer.
 *
 * On entry, the sizep argument points to the size of the output buffer.
 * On return, it is updated to the size of the message. If the message
 * doesn't fit in the output buffer, it is not popped, EMSGSIZE is
 * returned, but the sizep argument is updated nonetheless to let the
 * user know the message size, to potentially retry with a larger buffer.
 *
 * If the buffer is empty, EAGAIN is returned, and the size of the output
 * buffer is unmodified.
 *
 * The output buffer may be NULL, in which case this function acts as if
 * it wasn't, but without writing output data.
 */
int mbuf_pop(struct mbuf *mbuf, void *buf, size_t *sizep);

/*
 * Read a message from a message buffer.
 *
 * On entry, the indexp argument points to the index of the message to
 * read in the message buffer, and the sizep argument points to the size
 * of the output buffer. On return, if successful, indexp is updated
 * to the index of the next message, and sizep to the size of the
 * message read.
 *
 * If the message doesn't fit in the output buffer, it is not read,
 * EMSGSIZE is returned, and the sizep argument is updated nonetheless
 * to let the user know the message size, to potentially retry with a
 * larger buffer.
 *
 * If the given index refers to the end of the buffer, then EAGAIN is
 * returned. If it's outside buffer boundaries, EINVAL is returned.
 * Otherwise, if it doesn't point to the beginning of a message, the
 * behavior is undefined.
 *
 * The message buffer isn't changed by this operation.
 */
int mbuf_read(const struct mbuf *mbuf, size_t *indexp,
              void *buf, size_t *sizep);

#endif /* KERN_MBUF_H */
