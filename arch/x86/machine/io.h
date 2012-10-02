/*
 * Copyright (c) 2010 Richard Braun.
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

#ifndef _X86_IO_H
#define _X86_IO_H

#include <lib/stdint.h>

/*
 * Read a byte from an I/O port.
 */
static inline uint8_t
io_read_byte(uint16_t port)
{
    uint8_t value;

    asm volatile("inb %%dx, %%al" : "=a" (value) : "d" (port));
    return value;
}

/*
 * Write a byte to an I/O port.
 */
static inline void
io_write_byte(uint16_t port, uint8_t value)
{
    asm volatile("outb %%al, %%dx" : : "d" (port), "a" (value));
}

#endif /* _X86_IO_H */
