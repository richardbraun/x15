/*
 * Copyright (c) 2010-2017 Richard Braun.
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
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <kern/console.h>
#include <kern/error.h>
#include <kern/init.h>
#include <kern/cbuf.h>
#include <kern/macros.h>
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
#define CGA_MEMORY              0xb8000
#define CGA_MEMORY_LINE_SIZE    (CGA_COLUMNS * 2)
#define CGA_MEMORY_SIZE         (CGA_MEMORY_LINE_SIZE * CGA_LINES)

/*
 * I/O ports.
 */
#define CGA_PORT_MISC_OUT_READ          0x3cc
#define CGA_PORT_MISC_OUT_WRITE         0x3c2
#define CGA_PORT_CRTC_ADDR              0x3d4
#define CGA_PORT_CRTC_DATA              0x3d5

/*
 * Miscellaneous output register bits.
 */
#define CGA_MISC_OUT_IOAS               0x1

/*
 * CRTC registers.
 */
#define CGA_CRTC_CURSOR_START_REG       0xa
#define CGA_CRTC_CURSOR_LOC_HIGH_REG    0xe
#define CGA_CRTC_CURSOR_LOC_LOW_REG     0xf

/*
 * Cursor start register bits.
 */
#define CGA_CSR_DISABLED    0x10

/*
 * Foreground screen color.
 */
#define CGA_FOREGROUND_COLOR 0x7

/*
 * Number of spaces to display for a tabulation.
 */
#define CGA_TABULATION_SPACES 8

static void *cga_memory __read_mostly;

#define CGA_BACK_BUFFER_SIZE (64 * 1024)

#if CGA_BACK_BUFFER_SIZE < CGA_MEMORY_SIZE
#error "back buffer size must be at least as large as video memory"
#endif

#define CGA_SCROLL_PAGE ((CGA_LINES / 2) * CGA_MEMORY_LINE_SIZE)

/*
 * Back buffer.
 */
struct cga_bbuf {
    struct cbuf cbuf;
    size_t view;
    size_t cursor;
    char buf[CGA_BACK_BUFFER_SIZE];
    bool cursor_enabled;
};

static struct cga_bbuf cga_bbuf;

static uint16_t
cga_build_cell(char c)
{
    return (CGA_FOREGROUND_COLOR << 8) | c;
}

static void
cga_write(size_t index, const void *ptr, size_t size)
{
    assert((index + size) <= CGA_MEMORY_SIZE);
    memcpy(cga_memory + index, ptr, size);
}

static uint16_t
cga_get_cursor_position(void)
{
    uint16_t tmp;

    io_write_byte(CGA_PORT_CRTC_ADDR, CGA_CRTC_CURSOR_LOC_HIGH_REG);
    tmp = io_read_byte(CGA_PORT_CRTC_DATA) << 8;
    io_write_byte(CGA_PORT_CRTC_ADDR, CGA_CRTC_CURSOR_LOC_LOW_REG);
    tmp |= io_read_byte(CGA_PORT_CRTC_DATA);

    return tmp;
}

static void
cga_set_cursor_position(uint16_t position)
{
    io_write_byte(CGA_PORT_CRTC_ADDR, CGA_CRTC_CURSOR_LOC_HIGH_REG);
    io_write_byte(CGA_PORT_CRTC_DATA, position >> 8);
    io_write_byte(CGA_PORT_CRTC_ADDR, CGA_CRTC_CURSOR_LOC_LOW_REG);
    io_write_byte(CGA_PORT_CRTC_DATA, position & 0xff);
}

static void
cga_enable_cursor(void)
{
    uint8_t tmp;

    io_write_byte(CGA_PORT_CRTC_ADDR, CGA_CRTC_CURSOR_START_REG);
    tmp = io_read_byte(CGA_PORT_CRTC_DATA);
    io_write_byte(CGA_PORT_CRTC_DATA, tmp & ~CGA_CSR_DISABLED);
}

static void
cga_disable_cursor(void)
{
    uint8_t tmp;

    io_write_byte(CGA_PORT_CRTC_ADDR, CGA_CRTC_CURSOR_START_REG);
    tmp = io_read_byte(CGA_PORT_CRTC_DATA);
    io_write_byte(CGA_PORT_CRTC_DATA, tmp | CGA_CSR_DISABLED);
}

static void
cga_bbuf_init(struct cga_bbuf *bbuf, size_t cursor)
{
    cbuf_init(&bbuf->cbuf, bbuf->buf, sizeof(bbuf->buf));
    bbuf->view = cbuf_start(&bbuf->cbuf);
    cbuf_write(&bbuf->cbuf, bbuf->view, cga_memory, CGA_MEMORY_SIZE);
    bbuf->cursor = bbuf->view + cursor;
    bbuf->cursor_enabled = true;
}

static size_t
cga_bbuf_cursor_offset(const struct cga_bbuf *bbuf)
{
    return bbuf->cursor - bbuf->view;
}

static int
cga_bbuf_get_phys_cursor(const struct cga_bbuf *bbuf, uint16_t *cursorp)
{
    uint16_t cursor;

    cursor = cga_bbuf_cursor_offset(bbuf);
    assert((cursor & 1) == 0);

    if (cursor >= CGA_MEMORY_SIZE) {
        return ERROR_NODEV;
    }

    *cursorp = (cursor >> 1);
    return 0;
}

static void
cga_bbuf_update_phys_cursor(struct cga_bbuf *bbuf)
{
    bool cursor_enabled;
    uint16_t cursor = 0;
    int error;

    error = cga_bbuf_get_phys_cursor(bbuf, &cursor);
    cursor_enabled = !error;

    if (cursor_enabled != bbuf->cursor_enabled) {
        bbuf->cursor_enabled = cursor_enabled;

        if (cursor_enabled) {
            cga_enable_cursor();
        } else {
            cga_disable_cursor();
        }
    }

    if (cursor_enabled) {
        cga_set_cursor_position(cursor);
    }
}

static void
cga_bbuf_redraw(struct cga_bbuf *bbuf)
{
    size_t size;
    __unused int error;

    size = CGA_MEMORY_SIZE;
    error = cbuf_read(&bbuf->cbuf, bbuf->view, cga_memory, &size);
    assert(!error);
    assert(size == CGA_MEMORY_SIZE);
    cga_bbuf_update_phys_cursor(bbuf);
}

static bool
cga_bbuf_view_needs_scrolling(const struct cga_bbuf *bbuf)
{
    size_t view_size;

    view_size = cbuf_end(&bbuf->cbuf) - bbuf->view;

    if (view_size > CGA_MEMORY_SIZE) {
        return true;
    }

    /* Consider the cursor as a valid cell */
    view_size = (bbuf->cursor + 1) - bbuf->view;

    if (view_size > CGA_MEMORY_SIZE) {
        return true;
    }

    return false;
}

static void
cga_bbuf_scroll_once(struct cga_bbuf *bbuf)
{
    uint16_t spaces[CGA_COLUMNS];
    size_t i;

    for (i = 0; i < ARRAY_SIZE(spaces); i++) {
        spaces[i] = cga_build_cell(' ');
    }

    cbuf_write(&bbuf->cbuf, cbuf_end(&bbuf->cbuf), spaces, sizeof(spaces));
    bbuf->view += sizeof(spaces);
    cga_bbuf_redraw(bbuf);
}

static void
cga_bbuf_reset_view(struct cga_bbuf *bbuf)
{
    if ((bbuf->view + CGA_MEMORY_SIZE) == cbuf_end(&bbuf->cbuf)) {
        return;
    }

    bbuf->view = cbuf_end(&bbuf->cbuf) - CGA_MEMORY_SIZE;
    cga_bbuf_redraw(bbuf);
}

static void
cga_bbuf_push(struct cga_bbuf *bbuf, char c)
{
    size_t offset;
    uint16_t cell;

    cga_bbuf_reset_view(bbuf);

    cell = cga_build_cell(c);
    cbuf_write(&bbuf->cbuf, bbuf->cursor, &cell, sizeof(cell));
    offset = cga_bbuf_cursor_offset(bbuf);
    bbuf->cursor += sizeof(cell);

    if (cga_bbuf_view_needs_scrolling(bbuf)) {
        cga_bbuf_scroll_once(bbuf);
    } else {
        cga_write(offset, &cell, sizeof(cell));
        cga_bbuf_update_phys_cursor(bbuf);
    }
}

static void
cga_bbuf_newline(struct cga_bbuf *bbuf)
{
    uint16_t cursor = 0, spaces[CGA_COLUMNS];
    size_t i, nr_spaces, offset, size;
    __unused int error;

    cga_bbuf_reset_view(bbuf);

    error = cga_bbuf_get_phys_cursor(bbuf, &cursor);
    assert(!error);

    nr_spaces = CGA_COLUMNS - (cursor % CGA_COLUMNS);

    for (i = 0; i < nr_spaces; i++) {
        spaces[i] = cga_build_cell(' ');
    }

    /*
     * The cursor may not point at the end of the view, in which case
     * any existing data must be preserved.
     */
    size = sizeof(spaces);
    cbuf_read(&bbuf->cbuf, bbuf->cursor, spaces, &size);

    cbuf_write(&bbuf->cbuf, bbuf->cursor,
               spaces, nr_spaces * sizeof(spaces[0]));
    offset = cga_bbuf_cursor_offset(bbuf);
    bbuf->cursor += nr_spaces * sizeof(spaces[0]);

    if (cga_bbuf_view_needs_scrolling(bbuf)) {
        cga_bbuf_scroll_once(bbuf);
    } else {
        cga_write(offset, spaces, nr_spaces * sizeof(spaces[0]));
        cga_bbuf_update_phys_cursor(bbuf);
    }

    cga_bbuf_update_phys_cursor(bbuf);
}

static void
cga_bbuf_move_cursor(struct cga_bbuf *bbuf, bool forward)
{
    cga_bbuf_reset_view(bbuf);

    if ((!forward && (bbuf->cursor == bbuf->view))
        || (forward && (bbuf->cursor == cbuf_end(&bbuf->cbuf)))) {
        return;
    }

    if (forward) {
        bbuf->cursor += sizeof(uint16_t);
    } else {
        bbuf->cursor -= sizeof(uint16_t);
    }

    cga_bbuf_update_phys_cursor(bbuf);
}

static void
cga_bbuf_move_cursor_left(struct cga_bbuf *bbuf)
{
    cga_bbuf_move_cursor(bbuf, false);
}

static void
cga_bbuf_move_cursor_right(struct cga_bbuf *bbuf)
{
    cga_bbuf_move_cursor(bbuf, true);
}

static void
cga_bbuf_backspace(struct cga_bbuf *bbuf)
{
    cga_bbuf_move_cursor_left(bbuf);
}

static void
cga_bbuf_scroll_up(struct cga_bbuf *bbuf)
{
    size_t start, size;

    bbuf->view -= CGA_SCROLL_PAGE;

    /* The back buffer size is a power-of-two, not a line multiple */
    size = cbuf_size(&bbuf->cbuf);
    size -= size % CGA_MEMORY_LINE_SIZE;
    start = cbuf_end(&bbuf->cbuf) - size;

    if ((bbuf->view - start) >= size) {
        bbuf->view = start;
    }

    cga_bbuf_redraw(bbuf);
}

static void
cga_bbuf_scroll_down(struct cga_bbuf *bbuf)
{
    size_t end;

    bbuf->view += CGA_SCROLL_PAGE;
    end = bbuf->view + CGA_MEMORY_SIZE;

    if (!cbuf_range_valid(&bbuf->cbuf, bbuf->view, end)) {
        bbuf->view = cbuf_end(&bbuf->cbuf) - CGA_MEMORY_SIZE;
    }

    cga_bbuf_redraw(bbuf);
}

void
cga_putc(char c)
{
    unsigned int i;

    switch (c) {
    case '\r':
        return;
    case '\n':
        cga_bbuf_newline(&cga_bbuf);
        break;
    case '\b':
        cga_bbuf_backspace(&cga_bbuf);
        break;
    case '\t':
        for(i = 0; i < CGA_TABULATION_SPACES; i++) {
            cga_putc(' ');
        }

        break;
    case CONSOLE_SCROLL_UP:
        cga_bbuf_scroll_up(&cga_bbuf);
        break;
    case CONSOLE_SCROLL_DOWN:
        cga_bbuf_scroll_down(&cga_bbuf);
        break;
    default:
        cga_bbuf_push(&cga_bbuf, c);
    }
}

static void __init
cga_setup_misc_out(void)
{
    uint8_t reg;

    reg = io_read_byte(CGA_PORT_MISC_OUT_READ);

    if (!(reg & CGA_MISC_OUT_IOAS)) {
        reg |= CGA_MISC_OUT_IOAS;
        io_write_byte(CGA_PORT_MISC_OUT_WRITE, reg);
    }
}

static int __init
cga_setup(void)
{
    cga_memory = (void *)vm_page_direct_va(CGA_MEMORY);
    cga_setup_misc_out();
    cga_bbuf_init(&cga_bbuf, cga_get_cursor_position());
    return 0;
}

INIT_OP_DEFINE(cga_setup);

void
cga_cursor_left(void)
{
    cga_bbuf_move_cursor_left(&cga_bbuf);
}

void
cga_cursor_right(void)
{
    cga_bbuf_move_cursor_right(&cga_bbuf);
}
