/*
 * Copyright (c) 2010, 2012 Richard Braun.
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

#ifndef _I386_VGA_H
#define _I386_VGA_H

#include <lib/stdint.h>

/*
 * Initialize the vga module.
 */
void vga_setup(void);

/*
 * Write a byte on the screen at current cursor position.
 */
void vga_write_byte(uint8_t byte);

#endif /* _I386_VGA_H */
