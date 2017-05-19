/*
 * Copyright (c) 2010-2014 Richard Braun.
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

#include <stdint.h>
#include <string.h>

#include <kern/console.h>
#include <kern/init.h>
#include <kern/macros.h>
#include <kern/param.h>
#include <machine/io.h>
#include <machine/cga.h>
#include <vm/vm_page.h>

/*
 * Screen dimensions.
 */
#define CGA_COLUMNS 80
#define CGA_LINES   25

/*
 * Text mode mapped memory and size.
 */
#define CGA_MEMORY      0xb8000
#define CGA_MEMORY_SIZE (CGA_COLUMNS * CGA_LINES * 2)

/*
 * I/O ports.
 */
#define CGA_MISC_OUTPUT_REGISTER_READ   0x3cc
#define CGA_MISC_OUTPUT_REGISTER_WRITE  0x3c2
#define CGA_CRTC_ADDRESS_REGISTER       0x3d4
#define CGA_CRTC_DATA_REGISTER          0x3d5

/*
 * CRTC registers.
 */
#define CGA_CRTC_CURSOR_LOCATION_HIGH_REGISTER  0xe
#define CGA_CRTC_CURSOR_LOCATION_LOW_REGISTER   0xf

/*
 * Foreground screen color.
 */
#define CGA_FOREGROUND_COLOR 0x7

/*
 * Blank space 16 bits word.
 */
#define CGA_BLANK ((CGA_FOREGROUND_COLOR << 8) | ' ')

/*
 * Number of spaces to display for a tabulation.
 */
#define CGA_TABULATION_SPACES 8

static uint8_t *cga_memory __read_mostly;
static uint16_t cga_cursor;

static struct console cga_console;

static uint16_t
cga_get_cursor_position(void)
{
    uint16_t tmp;

    io_write_byte(CGA_CRTC_ADDRESS_REGISTER,
                  CGA_CRTC_CURSOR_LOCATION_HIGH_REGISTER);
    tmp = io_read_byte(CGA_CRTC_DATA_REGISTER) << 8;
    io_write_byte(CGA_CRTC_ADDRESS_REGISTER,
                  CGA_CRTC_CURSOR_LOCATION_LOW_REGISTER);
    tmp |= io_read_byte(CGA_CRTC_DATA_REGISTER);

    return tmp;
}

static void
cga_set_cursor_position(uint16_t position)
{
    io_write_byte(CGA_CRTC_ADDRESS_REGISTER,
                  CGA_CRTC_CURSOR_LOCATION_HIGH_REGISTER);
    io_write_byte(CGA_CRTC_DATA_REGISTER, position >> 8);
    io_write_byte(CGA_CRTC_ADDRESS_REGISTER,
                  CGA_CRTC_CURSOR_LOCATION_LOW_REGISTER);
    io_write_byte(CGA_CRTC_DATA_REGISTER, position & 0xff);
}

static uint8_t
cga_get_cursor_column(void)
{
    return cga_cursor % CGA_COLUMNS;
}

static void
cga_scroll_lines(void)
{
    uint16_t *last_line;
    int i;

    memmove(cga_memory, (uint16_t *)cga_memory + CGA_COLUMNS,
            CGA_MEMORY_SIZE - (CGA_COLUMNS * 2));
    last_line = (uint16_t *)cga_memory + (CGA_COLUMNS * (CGA_LINES - 1));

    for(i = 0; i < CGA_COLUMNS; i++) {
        last_line[i] = CGA_BLANK;
    }
}

static void
cga_write_char(char c)
{
    if (c == '\r') {
        return;
    } else if (c == '\n') {
        cga_cursor += CGA_COLUMNS - cga_get_cursor_column();

        if (cga_cursor >= (CGA_LINES * CGA_COLUMNS)) {
            cga_scroll_lines();
            cga_cursor -= CGA_COLUMNS;
        }

        cga_set_cursor_position(cga_cursor);
    } else if (c == '\b') {
        if (cga_cursor > 0) {
            cga_cursor--;
            ((uint16_t *)cga_memory)[cga_cursor] = CGA_BLANK;
            cga_set_cursor_position(cga_cursor);
        }
    } else if (c == '\t') {
        int i;

        for(i = 0; i < CGA_TABULATION_SPACES; i++) {
            cga_write_char(' ');
        }
    } else {
        if ((cga_cursor + 1) >= CGA_COLUMNS * CGA_LINES) {
            cga_scroll_lines();
            cga_cursor -= CGA_COLUMNS;
        }

        ((uint16_t *)cga_memory)[cga_cursor] = ((CGA_FOREGROUND_COLOR << 8)
                                                | c);
        cga_cursor++;
        cga_set_cursor_position(cga_cursor);
    }
}

static void
cga_console_putc(struct console *console, char c)
{
    (void)console;
    cga_write_char(c);
}

void __init
cga_setup(void)
{
    uint8_t misc_output_register;

    cga_memory = (void *)vm_page_direct_va(CGA_MEMORY);

    /*
     * Check if the Input/Output Address Select bit is set.
     */
    misc_output_register = io_read_byte(CGA_MISC_OUTPUT_REGISTER_READ);

    if (!(misc_output_register & 0x1)) {
        /*
         * Set the I/O AS bit.
         */
        misc_output_register |= 0x1;

        /*
         * Update the misc output register.
         */
        io_write_byte(CGA_MISC_OUTPUT_REGISTER_WRITE, misc_output_register);
    }

    cga_cursor = cga_get_cursor_position();

    console_init(&cga_console, cga_console_putc);
    console_register(&cga_console);
}
