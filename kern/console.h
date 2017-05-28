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
 * Device-independent console interface.
 */

#ifndef _KERN_CONSOLE_H
#define _KERN_CONSOLE_H

#include <kern/cbuf.h>
#include <kern/list.h>
#include <kern/spinlock.h>
#include <kern/thread.h>

struct console;

struct console_ops {
    void (*putc)(struct console *console, char c);
};

#define CONSOLE_BUF_SIZE    64
#define CONSOLE_NAME_SIZE   16

/*
 * Console device.
 *
 * This structure should be embedded in the hardware-specific console
 * objects. Calls to console operations are all serialized by this module
 * for each device. Interrupts are disabled when calling operations.
 */
struct console {
    struct spinlock lock;
    const struct console_ops *ops;
    char buffer[CONSOLE_BUF_SIZE];
    struct cbuf recvbuf;
    struct thread *waiter;
    struct list node;
    char name[CONSOLE_NAME_SIZE];
};

/*
 * Console initialization.
 */
void console_init(struct console *console, const char *name,
                  const struct console_ops *ops);

/*
 * Initialize the console module.
 */
void console_setup(void);

/*
 * Register a console device.
 *
 * The given console must be initialized before calling this function.
 *
 * This function isn't thread-safe and can only be called during system
 * initialization.
 */
void console_register(struct console *console);

/*
 * Console interrupt handler.
 *
 * This function is meant to be used by low-level drivers to fill the
 * receive buffer.
 *
 * Interrupts must be disabled when calling this function.
 */
void console_intr(struct console *console, char c);

/*
 * Write/read a single character to all registered console devices.
 *
 * Writing may not block in order to allow printf functions to be used in any
 * context. Reading may block waiting for input.
 */
void console_putchar(char c);
char console_getchar(void);

#endif /* _KERN_CONSOLE_H */
