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

#include <kern/list.h>
#include <kern/spinlock.h>

struct console;

/*
 * Type for character writing functions.
 */
typedef void (*console_putc_fn)(struct console *console, char c);

/*
 * Console device.
 *
 * This structure should be embedded in the hardware-specific console
 * objects. Calls to console operations are all serialized by this module
 * for each device.
 */
struct console {
    struct spinlock lock;
    struct list node;
    console_putc_fn putc;
};

static inline void
console_init(struct console *console, console_putc_fn putc)
{
    spinlock_init(&console->lock);
    console->putc = putc;
}

/*
 * Initialize the console module.
 */
void console_setup(void);

/*
 * Register a console device.
 *
 * The given console must be initialized before calling this function.
 */
void console_register(struct console *console);

/*
 * Write a single character to all registered console devices.
 */
void console_write_char(char c);

#endif /* _KERN_CONSOLE_H */
