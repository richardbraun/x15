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

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <kern/arg.h>
#include <kern/assert.h>
#include <kern/init.h>
#include <kern/console.h>
#include <kern/list.h>
#include <kern/spinlock.h>

/*
 * Registered consoles.
 */
static struct list console_devs;

/*
 * Active console device.
 */
static struct console *console_dev;

static const char *console_name __initdata;

static bool __init
console_name_match(const char *name)
{
    if (console_name == NULL) {
        return true;
    }

    return (strcmp(console_name, name) == 0);
}

void __init
console_init(struct console *console, const char *name,
             console_putc_fn putc)
{
    spinlock_init(&console->lock);
    console->putc = putc;
    strlcpy(console->name, name, sizeof(console->name));
}

static void
console_putc(struct console *console, char c)
{
    unsigned long flags;

    spinlock_lock_intr_save(&console->lock, &flags);
    console->putc(console, c);
    spinlock_unlock_intr_restore(&console->lock, flags);
}

void __init
console_setup(void)
{
    list_init(&console_devs);
    console_name = arg_value("console");
}

void __init
console_register(struct console *console)
{
    list_insert_tail(&console_devs, &console->node);

    if ((console_dev == NULL) && console_name_match(console->name)) {
        console_dev = console;
    }

    printf("console: %s registered\n", console->name);

    if (console == console_dev) {
        printf("console: %s selected as active console\n", console->name);
    }
}

void
console_write_char(char c)
{
    if (console_dev == NULL) {
        return;
    }

    console_putc(console_dev, c);
}
