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
 */

#include <assert.h>
#include <stdint.h>

#include <kern/arg.h>
#include <kern/console.h>
#include <kern/error.h>
#include <kern/init.h>
#include <kern/intr.h>
#include <kern/log.h>
#include <kern/macros.h>
#include <machine/biosmem.h>
#include <machine/io.h>
#include <machine/uart.h>

#define UART_BDA_COM1_OFFSET 0

#define UART_REG_DAT            0
#define UART_REG_DLL            0
#define UART_REG_IER            1
#define UART_REG_DLH            1
#define UART_REG_IIR            2
#define UART_REG_LCR            3
#define UART_REG_MCR            4
#define UART_REG_LSR            5
#define UART_REG_MSR            6
#define UART_NR_REGS            7

#define UART_IER_RX             0x1

#define UART_IIR_NOT_PENDING    0x1
#define UART_IIR_SRC_RX         0x4
#define UART_IIR_SRC_MASK       0xe

#define UART_LCR_8BITS          0x03
#define UART_LCR_1S             0x00
#define UART_LCR_NP             0x00
#define UART_LCR_OP             0x08
#define UART_LCR_EP             0x18
#define UART_LCR_BEN            0x40
#define UART_LCR_DLAB           0x80

#define UART_MCR_DTR            0x01
#define UART_MCR_RTS            0x02
#define UART_MCR_AUX2           0x04

#define UART_LSR_DATA_READY     0x01
#define UART_LSR_TX_EMPTY       0x20

#define UART_MAX_DEVS           4

#define UART_SPEED_MAX          115200
#define UART_SPEED_DEFAULT      UART_SPEED_MAX

enum {
    UART_PARITY_NONE,
    UART_PARITY_ODD,
    UART_PARITY_EVEN,
};

#define UART_PARITY_DEFAULT     UART_PARITY_NONE

#define UART_DATA_BITS_DEFAULT  8

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
uart_recv_intr(struct uart *uart)
{
    uint8_t byte;
    char tmp[2];

    tmp[1] = '\0';

    for (;;) {
        byte = uart_read(uart, UART_REG_LSR);

        if (!(byte & UART_LSR_DATA_READY)) {
            break;
        }

        byte = uart_read(uart, UART_REG_DAT);
        tmp[0] = (char)byte;
        console_intr(&uart->console, tmp);
    }
}

static int
uart_intr(void *arg)
{
    struct uart *uart;
    uint8_t byte;

    uart = arg;

    byte = uart_read(uart, UART_REG_IIR);

    if (byte & UART_IIR_NOT_PENDING) {
        return ERROR_AGAIN;
    }

    byte &= UART_IIR_SRC_MASK;

    if (byte == UART_IIR_SRC_RX) {
        uart_recv_intr(uart);
    }

    return 0;
}

static void __init
uart_enable_intr(struct uart *uart)
{
    int error;

    error = intr_register(uart->intr, uart_intr, uart);

    if (error) {
        log_err("uart%zu: unable to register interrupt %u",
                 uart_get_id(uart), uart->intr);
        return;
    }

    uart_write(uart, UART_REG_IER, UART_IER_RX);
}

static void
uart_tx_wait(struct uart *uart)
{
    uint8_t byte;

    for (;;) {
        byte = uart_read(uart, UART_REG_LSR);

        if (byte & UART_LSR_TX_EMPTY) {
            break;
        }
    }
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
uart_console_putc(struct console *console, char c)
{
    uart_write_char(uart_get_from_console(console), c);
}

static const struct console_ops uart_console_ops = {
    .putc = uart_console_putc,
};

static void __init
uart_init_default(unsigned int *speed, unsigned int *parity,
                  unsigned int *data_bits)
{
    *speed = UART_SPEED_DEFAULT;
    *parity = UART_PARITY_DEFAULT;
    *data_bits = UART_DATA_BITS_DEFAULT;
}

static int __init
uart_init_check_speed(unsigned int speed)
{
    if (speed > UART_SPEED_MAX) {
        return ERROR_INVAL;
    }

    return 0;
}

static int __init
uart_init_convert_parity_char(char c, unsigned int *parity)
{
    switch (c) {
    case 'n':
        *parity = UART_PARITY_NONE;
        break;
    case 'o':
        *parity = UART_PARITY_ODD;
        break;
    case 'e':
        *parity = UART_PARITY_EVEN;
        break;
    default:
        return ERROR_INVAL;
    }

    return 0;
}

static int __init
uart_init_check_data_bits(unsigned int data_bits)
{
    switch (data_bits) {
    case 5 ... 8:
        break;
    default:
        return ERROR_INVAL;
    }

    return 0;
}

static void __init
uart_init_args(const struct uart *uart, const char *arg_str,
               unsigned int *speed, unsigned int *parity,
               unsigned int *data_bits)
{
    char parity_char;
    int ret, error;

    ret = sscanf(arg_str, "%u%c%1u", speed, &parity_char, data_bits);

    if (ret < 1) {
        goto set_defaults;
    }

    error = uart_init_check_speed(*speed);

    if (error) {
        goto set_defaults;
    } else if (ret < 2) {
        return;
    }

    error = uart_init_convert_parity_char(parity_char, parity);

    if (error) {
        goto set_defaults;
    } else if (ret < 3) {
        return;
    }

    error = uart_init_check_data_bits(*data_bits);

    if (error) {
        goto set_defaults;
    }

    return;

set_defaults:
    log_warning("uart%zu: invalid serial configuration, using defaults",
                uart_get_id(uart));
    uart_init_default(speed, parity, data_bits);
}

static void __init
uart_init(struct uart *uart, uint16_t port, uint16_t intr)
{
    unsigned int speed, parity, data_bits;
    const char *arg_str;
    char name[CONSOLE_NAME_SIZE];
    uint16_t divisor;
    uint8_t byte;

    snprintf(name, sizeof(name), "uart%zu", uart_get_id(uart));
    arg_str = arg_value(name);

    uart_init_default(&speed, &parity, &data_bits);

    if (arg_str != NULL) {
        uart_init_args(uart, arg_str, &speed, &parity, &data_bits);
    }

    log_debug("uart%zu: speed:%u parity:%u data_bits:%u",
              uart_get_id(uart), speed, parity, data_bits);

    uart->port = port;
    uart->intr = intr;

    uart_write(uart, UART_REG_IER, 0);

    divisor = UART_SPEED_MAX / speed;

    uart_set(uart, UART_REG_LCR, UART_LCR_DLAB);
    uart_write(uart, UART_REG_DLH, divisor >> 8);
    uart_write(uart, UART_REG_DLL, divisor & 0xff);
    uart_clear(uart, UART_REG_LCR, UART_LCR_DLAB);

    uart_write(uart, UART_REG_MCR, UART_MCR_AUX2 | UART_MCR_RTS | UART_MCR_DTR);

    byte = UART_LCR_1S;

    switch (parity) {
    case UART_PARITY_NONE:
        byte |= UART_LCR_NP;
        break;
    case UART_PARITY_ODD:
        byte |= UART_LCR_OP;
        break;
    case UART_PARITY_EVEN:
        byte |= UART_LCR_EP;
        break;
    }

    byte |= (data_bits - 5);
    uart_write(uart, UART_REG_LCR, byte);

    console_init(&uart->console, name, &uart_console_ops);
    console_register(&uart->console);
}

static void __init
uart_log_info(void)
{
    const struct uart *uart;
    size_t i;

    for (i = 0; i < ARRAY_SIZE(uart_devs); i++) {
        uart = uart_get_dev(i);

        if (uart->port != 0) {
            log_info("uart%zu: port:%#x irq:%u", i, (unsigned int)uart->port,
                     (unsigned int)uart->intr);
        }
    }
}

static int __init
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

    uart_log_info();
    return 0;
}

INIT_OP_DEFINE(uart_bootstrap,
               INIT_OP_DEP(arg_setup, true),
               INIT_OP_DEP(console_bootstrap, true),
               INIT_OP_DEP(log_setup, true));

static int __init
uart_setup(void)
{
    struct uart *uart;
    size_t i;

    for (i = 0; i < ARRAY_SIZE(uart_devs); i++) {
        uart = uart_get_dev(i);

        if (uart->port == 0) {
            continue;
        }

        uart_enable_intr(uart);
    }

    return 0;
}

INIT_OP_DEFINE(uart_setup,
               INIT_OP_DEP(intr_setup, true),
               INIT_OP_DEP(uart_bootstrap, true));
