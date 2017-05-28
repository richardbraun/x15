/*
 * Copyright (c) 2012-2017 Richard Braun.
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
#include <kern/error.h>
#include <kern/init.h>
#include <kern/intr.h>
#include <kern/panic.h>
#include <machine/cpu.h>
#include <machine/io.h>
#include <machine/lapic.h>
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
#define PIC_MAX_INTR        ((PIC_NR_INTRS * 2) - 1)

static unsigned int pic_nr_slave_intrs;

static uint8_t pic_master_mask;
static uint8_t pic_slave_mask;

static uint8_t pic_master_spurious_intr;
static uint8_t pic_slave_spurious_intr;

static bool
pic_is_slave_intr(unsigned int intr)
{
    assert(intr <= PIC_MAX_INTR);
    return (intr >= PIC_NR_INTRS);
}

static void
pic_inc_slave_intrs(void)
{
    if (pic_nr_slave_intrs == 0) {
        pic_master_mask |= 1 << PIC_SLAVE_INTR;
        io_write_byte(PIC_MASTER_IMR, pic_master_mask);
    }

    pic_nr_slave_intrs++;
    assert(pic_nr_slave_intrs != 0);
}

static void
pic_dec_slave_intrs(void)
{
    assert(pic_nr_slave_intrs != 0);

    pic_nr_slave_intrs--;

    if (pic_nr_slave_intrs == 0) {
        pic_master_mask &= ~(1 << PIC_SLAVE_INTR);
        io_write_byte(PIC_MASTER_IMR, pic_master_mask);
    }
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

static void
pic_ops_enable(void *priv, unsigned int intr, unsigned int cpu)
{
    (void)priv;
    (void)cpu;

    if (pic_is_slave_intr(intr)) {
        pic_slave_mask &= ~(1 << (intr - PIC_NR_INTRS));
        io_write_byte(PIC_SLAVE_IMR, pic_slave_mask);
        pic_inc_slave_intrs();
    } else {
        pic_master_mask &= ~(1 << intr);
        io_write_byte(PIC_MASTER_IMR, pic_master_mask);
    }
}

static void
pic_ops_disable(void *priv, unsigned int intr)
{
    (void)priv;

    if (pic_is_slave_intr(intr)) {
        pic_dec_slave_intrs();
        pic_slave_mask |= 1 << (intr - PIC_NR_INTRS);
        io_write_byte(PIC_SLAVE_IMR, pic_slave_mask);
    } else {
        pic_master_mask |= 1 << intr;
        io_write_byte(PIC_MASTER_IMR, pic_master_mask);
    }
}

static void
pic_ops_eoi(void *priv, unsigned int intr)
{
    (void)priv;
    pic_eoi(intr);
}

static const struct intr_ops pic_ops = {
    .enable = pic_ops_enable,
    .disable = pic_ops_disable,
    .eoi = pic_ops_eoi,
};

static void
pic_intr(struct trap_frame *frame)
{
    intr_handle(frame->vector - TRAP_INTR_FIRST);
}

static void __init
pic_register(void)
{
    unsigned int intr;

    intr_register_ctl(&pic_ops, NULL, 0, PIC_MAX_INTR);

    for (intr = 0; intr <= PIC_MAX_INTR; intr++) {
        trap_register(TRAP_INTR_FIRST + intr, pic_intr);
    }
}

static int
pic_spurious_intr(void *arg)
{
    uint8_t intr, isr;

    intr = *(const uint8_t *)arg;

    if (arg == &pic_master_spurious_intr) {
        isr = pic_read_isr(PIC_MASTER_CMD);

        if (isr & (1 << PIC_SPURIOUS_INTR)) {
            panic("pic: real interrupt %hhu", intr);
        }
    } else {
        isr = pic_read_isr(PIC_SLAVE_CMD);

        if (isr & (1 << PIC_SPURIOUS_INTR)) {
            panic("pic: real interrupt %hhu", intr);
        }

        pic_eoi(PIC_SLAVE_INTR);
    }

    return 0;
}

void __init
pic_setup(void)
{
    int error;

    pic_nr_slave_intrs = 0;
    pic_master_mask = 0xff;
    pic_slave_mask = 0xff;

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
    io_write_byte(PIC_MASTER_IMR, pic_master_mask);
    io_write_byte(PIC_SLAVE_IMR, pic_slave_mask);

    if (lapic_unused()) {
        pic_register();
    }

    pic_master_spurious_intr = PIC_SPURIOUS_INTR;
    error = intr_register(pic_master_spurious_intr, pic_spurious_intr,
                          &pic_master_spurious_intr);
    error_check(error, __func__);

    pic_slave_spurious_intr = PIC_NR_INTRS + PIC_SPURIOUS_INTR;
    error = intr_register(pic_slave_spurious_intr, pic_spurious_intr,
                          &pic_slave_spurious_intr);
    error_check(error, __func__);
}
