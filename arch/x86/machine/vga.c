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

#include <kern/init.h>
#include <kern/macros.h>
#include <kern/stdint.h>
#include <kern/string.h>
#include <machine/io.h>
#include <machine/pmap.h>
#include <machine/vga.h>

/*
 * Screen dimensions.
 */
#define VGA_COLUMNS 80
#define VGA_LINES   25

/*
 * Text mode mapped memory and size.
 */
#define VGA_MEMORY      0xb8000
#define VGA_MEMORY_SIZE (VGA_COLUMNS * VGA_LINES * 2)

/*
 * I/O ports.
 */
#define VGA_MISC_OUTPUT_REGISTER_READ   0x3cc
#define VGA_MISC_OUTPUT_REGISTER_WRITE  0x3c2
#define VGA_CRTC_ADDRESS_REGISTER       0x3d4
#define VGA_CRTC_DATA_REGISTER          0x3d5

/*
 * CRTC registers.
 */
#define VGA_CRTC_CURSOR_LOCATION_HIGH_REGISTER  0xe
#define VGA_CRTC_CURSOR_LOCATION_LOW_REGISTER   0xf

/*
 * Foreground screen color.
 */
#define VGA_FOREGROUND_COLOR 0x7

/*
 * Blank space 16 bits word.
 */
#define VGA_BLANK ((VGA_FOREGROUND_COLOR << 8) | ' ')

/*
 * Number of spaces to display for a tabulation.
 */
#define VGA_TABULATION_SPACES 8

static uint8_t *vga_memory;
static uint16_t vga_cursor;

static uint16_t
vga_get_cursor_position(void)
{
    uint16_t tmp;

    io_write_byte(VGA_CRTC_ADDRESS_REGISTER,
                  VGA_CRTC_CURSOR_LOCATION_HIGH_REGISTER);
    tmp = io_read_byte(VGA_CRTC_DATA_REGISTER) << 8;
    io_write_byte(VGA_CRTC_ADDRESS_REGISTER,
                  VGA_CRTC_CURSOR_LOCATION_LOW_REGISTER);
    tmp |= io_read_byte(VGA_CRTC_DATA_REGISTER);

    return tmp;
}

static void
vga_set_cursor_position(uint16_t position)
{
    io_write_byte(VGA_CRTC_ADDRESS_REGISTER,
                  VGA_CRTC_CURSOR_LOCATION_HIGH_REGISTER);
    io_write_byte(VGA_CRTC_DATA_REGISTER, position >> 8);
    io_write_byte(VGA_CRTC_ADDRESS_REGISTER,
                  VGA_CRTC_CURSOR_LOCATION_LOW_REGISTER);
    io_write_byte(VGA_CRTC_DATA_REGISTER, position & 0xff);
}

static uint8_t
vga_get_cursor_column(void)
{
    return vga_cursor % VGA_COLUMNS;
}

void __init
vga_setup(void)
{
    uint8_t misc_output_register;
    unsigned long va;

    va = pmap_bootalloc(1);
    pmap_kenter(va, VGA_MEMORY);
    vga_memory = (uint8_t *)va;

    /*
     * Check if the Input/Output Address Select bit is set.
     */
    misc_output_register = io_read_byte(VGA_MISC_OUTPUT_REGISTER_READ);

    if (!(misc_output_register & 0x1)) {
        /*
         * Set the I/O AS bit.
         */
        misc_output_register |= 0x1;

        /*
         * Update the misc output register.
         */
        io_write_byte(VGA_MISC_OUTPUT_REGISTER_WRITE, misc_output_register);
    }

    vga_cursor = vga_get_cursor_position();
}

static void
vga_scroll_lines(void)
{
    uint16_t *last_line;
    int i;

    memmove(vga_memory, (uint16_t *)vga_memory + VGA_COLUMNS,
            VGA_MEMORY_SIZE - (VGA_COLUMNS * 2));
    last_line = (uint16_t *)vga_memory + (VGA_COLUMNS * (VGA_LINES - 1));

    for(i = 0; i < VGA_COLUMNS; i++)
        last_line[i] = VGA_BLANK;
}

void
vga_write_byte(uint8_t byte)
{
    if (byte == '\r')
        return;
    else if (byte == '\n') {
        vga_cursor += VGA_COLUMNS - vga_get_cursor_column();

        if (vga_cursor >= (VGA_LINES * VGA_COLUMNS)) {
            vga_scroll_lines();
            vga_cursor -= VGA_COLUMNS;
        }

        vga_set_cursor_position(vga_cursor);
    } else if (byte == '\b') {
        if (vga_cursor > 0) {
            vga_cursor--;
            ((uint16_t *)vga_memory)[vga_cursor] = VGA_BLANK;
            vga_set_cursor_position(vga_cursor);
        }
    } else if (byte == '\t') {
        int i;

        for(i = 0; i < VGA_TABULATION_SPACES; i++)
            vga_write_byte(' ');
    } else {
        if ((vga_cursor + 1) >= VGA_COLUMNS * VGA_LINES) {
            vga_scroll_lines();
            vga_cursor -= VGA_COLUMNS;
        }

        ((uint16_t *)vga_memory)[vga_cursor] = ((VGA_FOREGROUND_COLOR << 8)
                                                | byte);
        vga_cursor++;
        vga_set_cursor_position(vga_cursor);
    }
}

void console_write_byte(char c) __alias("vga_write_byte");
