/*
 * Copyright (c) 2017 Richard Braun.
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
 * TODO Make serial line parameters configurable.
 * TODO 16550A support.
 * TODO Interrupt probing and handling.
 */

#include <stdint.h>
#include <stdio.h>

#include <kern/assert.h>
#include <kern/console.h>
#include <kern/init.h>
#include <kern/intr.h>
#include <kern/macros.h>
#include <machine/biosmem.h>
#include <machine/io.h>
#include <machine/uart.h>

#define UART_BDA_COM1_OFFSET 0

#define UART_REG_DAT    0
#define UART_REG_DLL    0
#define UART_REG_IER    1
#define UART_REG_DLH    1
#define UART_REG_LCR    3
#define UART_REG_MCR    4
#define UART_REG_LSR    5
#define UART_NR_REGS    6

#define UART_THR_EMPTY  0x20

#define UART_LCR_8BITS  0x03
#define UART_LCR_1S     0x00
#define UART_LCR_NP     0x00
#define UART_LCR_BEN    0x40
#define UART_LCR_DLAB   0x80

#define UART_MCR_DTR    0x01
#define UART_MCR_RTS    0x02
#define UART_MCR_AUX2   0x04

#define UART_MAX_DEVS   4

struct uart {
    struct console console;
    uint16_t port;
    uint16_t intr;
};

static struct uart uart_devs[UART_MAX_DEVS];

static uint16_t uart_intrs[UART_MAX_DEVS] = { 4, 3, 4, 3 };

static size_t
uart_get_id(const struct uart *uart)
{
    size_t id;

    id = uart - uart_devs;
    assert(id < ARRAY_SIZE(uart_devs));
    return id;
}

static uint16_t
uart_get_addr(const struct uart *uart, uint16_t reg)
{
    assert(reg < UART_NR_REGS);
    return uart->port + reg;
}

static uint8_t
uart_read(struct uart *uart, uint16_t reg)
{
    return io_read_byte(uart_get_addr(uart, reg));
}

static void
uart_write(struct uart *uart, uint16_t reg, uint8_t byte)
{
    io_write_byte(uart_get_addr(uart, reg), byte);
}

static void
uart_set(struct uart *uart, uint16_t reg, uint8_t mask)
{
    uint16_t addr;
    uint8_t byte;

    addr = uart_get_addr(uart, reg);
    byte = io_read_byte(addr);
    byte |= mask;
    io_write_byte(addr, byte);
}

static void
uart_clear(struct uart *uart, uint16_t reg, uint8_t mask)
{
    uint16_t addr;
    uint8_t byte;

    addr = uart_get_addr(uart, reg);
    byte = io_read_byte(addr);
    byte &= ~mask;
    io_write_byte(addr, byte);
}

static void
uart_tx_wait(struct uart *uart)
{
    uint8_t byte;

    for (;;) {
        byte = uart_read(uart, UART_REG_LSR);

        if (byte & UART_THR_EMPTY) {
            break;
        }
    }
}

static struct uart *
uart_get_dev(size_t i)
{
    assert(i < ARRAY_SIZE(uart_devs));
    return &uart_devs[i];
}

static struct uart *
uart_get_from_console(struct console *console)
{
    return structof(console, struct uart, console);
}

static void
uart_write_char_common(struct uart *uart, char c)
{
    uart_tx_wait(uart);
    uart_write(uart, UART_REG_DAT, (uint8_t)c);
}

static void
uart_write_char(struct uart *uart, char c)
{
    if (c == '\n') {
        uart_write_char_common(uart, '\r');
    }

    uart_write_char_common(uart, c);
}

static void
uart_console_putc(struct console *console, char c)
{
    uart_write_char(uart_get_from_console(console), c);
}

static struct console_ops uart_console_ops = {
    .putc = uart_console_putc,
};

static void __init
uart_init(struct uart *uart, uint16_t port, uint16_t intr)
{
    char name[CONSOLE_NAME_SIZE];
    uint8_t byte;

    uart->port = port;
    uart->intr = intr;

    uart_write(uart, UART_REG_IER, 0);
    uart_write(uart, UART_REG_MCR, UART_MCR_AUX2 | UART_MCR_RTS | UART_MCR_DTR);

    uart_set(uart, UART_REG_LCR, UART_LCR_DLAB);
    uart_write(uart, UART_REG_DLH, 0);
    uart_write(uart, UART_REG_DLL, 1);
    uart_clear(uart, UART_REG_LCR, UART_LCR_DLAB);

    byte = UART_LCR_8BITS | UART_LCR_NP | UART_LCR_1S | UART_LCR_BEN;
    uart_write(uart, UART_REG_LCR, byte);

    snprintf(name, sizeof(name), "uart%zu", uart_get_id(uart));
    console_init(&uart->console, name, &uart_console_ops);
    console_register(&uart->console);
}

void __init
uart_bootstrap(void)
{
    const uint16_t *ptr;
    size_t i;

    ptr = biosmem_get_bda() + UART_BDA_COM1_OFFSET;

    for (i = 0; i < UART_MAX_DEVS; i++) {
        if (ptr[i] == 0) {
            continue;
        }

        uart_init(uart_get_dev(i), ptr[i], uart_intrs[i]);
    }
}

static int
uart_intr(void *arg)
{
    struct uart *uart;
    uint8_t byte;

    uart = arg;
    byte = uart_read(uart, UART_REG_DAT);
    printf("uart: intr:%u byte:%hhu (%c)\n", uart->intr, byte, byte);
    return 0;
}

void __init
uart_setup(void)
{
    struct uart *uart;
    int error;
    size_t i;

    for (i = 0; i < ARRAY_SIZE(uart_devs); i++) {
        uart = uart_get_dev(i);

        if (uart->port == 0) {
            continue;
        }

        error = intr_register(uart->intr, uart_intr, uart);

        if (error) {
            printf("uart%zu: unable to register interrupt %u\n", i, uart->intr);
        }

        uart_write(uart, UART_REG_IER, 1);
    }
}

void __init
uart_info(void)
{
    const struct uart *uart;
    size_t i;

    for (i = 0; i < ARRAY_SIZE(uart_devs); i++) {
        uart = uart_get_dev(i);

        if (uart->port != 0) {
            printf("uart%zu: port:%#x irq:%u\n", i, (unsigned int)uart->port,
                   (unsigned int)uart->intr);
        }
    }
}
