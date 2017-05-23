/*
 * Copyright (c) 2012-2014 Richard Braun.
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

#include <kern/assert.h>
#include <kern/init.h>
#include <kern/panic.h>
#include <machine/io.h>
#include <machine/cpu.h>
#include <machine/pic.h>
#include <machine/trap.h>

/*
 * I/O ports.
 */
#define PIC_MASTER_CMD      0x20
#define PIC_MASTER_IMR      0x21
#define PIC_SLAVE_CMD       0xa0
#define PIC_SLAVE_IMR       0xa1

/*
 * Register bits.
 */
#define PIC_ICW1_IC4        0x01
#define PIC_ICW1_INIT       0x10
#define PIC_ICW4_8086       0x01
#define PIC_OCW3_ISR        0x0b
#define PIC_EOI             0x20

/*
 * Special interrupts.
 */
#define PIC_SLAVE_INTR      2
#define PIC_SPURIOUS_INTR   7
#define PIC_NR_INTRS        8

void __init
pic_setup(void)
{
    /* ICW 1 - State that ICW 4 will be sent */
    io_write_byte(PIC_MASTER_CMD, PIC_ICW1_INIT | PIC_ICW1_IC4);
    io_write_byte(PIC_SLAVE_CMD, PIC_ICW1_INIT | PIC_ICW1_IC4);

    /* ICW 2 */
    io_write_byte(PIC_MASTER_IMR, TRAP_INTR_FIRST);
    io_write_byte(PIC_SLAVE_IMR, TRAP_INTR_FIRST + PIC_NR_INTRS);

    /* ICW 3 - Set up cascading */
    io_write_byte(PIC_MASTER_IMR, 1 << PIC_SLAVE_INTR);
    io_write_byte(PIC_SLAVE_IMR, PIC_SLAVE_INTR);

    /* ICW 4 - Set 8086 mode */
    io_write_byte(PIC_MASTER_IMR, PIC_ICW4_8086);
    io_write_byte(PIC_SLAVE_IMR, PIC_ICW4_8086);

    /* OCW 1 - Mask all interrupts */
    io_write_byte(PIC_MASTER_IMR, 0xff);
    io_write_byte(PIC_SLAVE_IMR, 0xff);
}

static void
pic_eoi(unsigned long intr)
{
    if (intr >= PIC_NR_INTRS) {
        io_write_byte(PIC_SLAVE_CMD, PIC_EOI);
    }

    io_write_byte(PIC_MASTER_CMD, PIC_EOI);
}

static uint8_t
pic_read_isr(uint16_t port)
{
    io_write_byte(port, PIC_OCW3_ISR);
    return io_read_byte(port);
}

void
pic_spurious_intr(struct trap_frame *frame)
{
    unsigned long intr;
    uint8_t isr;

    intr = frame->vector - TRAP_INTR_FIRST;
    assert((intr == PIC_SPURIOUS_INTR)
           || (intr == (PIC_NR_INTRS + PIC_SPURIOUS_INTR)));

    if (intr == PIC_SPURIOUS_INTR) {
        isr = pic_read_isr(PIC_MASTER_CMD);

        if (isr & (1 << PIC_SPURIOUS_INTR)) {
            panic("pic: real interrupt %lu", intr);
        }
    } else {
        isr = pic_read_isr(PIC_SLAVE_CMD);

        if (isr & (1 << PIC_SPURIOUS_INTR)) {
            panic("pic: real interrupt %lu", intr);
        }

        pic_eoi(PIC_SLAVE_INTR);
    }
}
