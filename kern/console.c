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

#include <stddef.h>

#include <kern/assert.h>
#include <kern/init.h>
#include <kern/console.h>
#include <kern/list.h>
#include <kern/spinlock.h>

static struct list console_devs;
static struct spinlock console_lock;

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
    spinlock_init(&console_lock);
}

void __init
console_register(struct console *console)
{
    assert(console->putc != NULL);

    spinlock_lock(&console_lock);
    list_insert_tail(&console_devs, &console->node);
    spinlock_unlock(&console_lock);
}

void
console_write_char(char c)
{
    struct console *console;
    unsigned long flags;

    spinlock_lock_intr_save(&console_lock, &flags);

    list_for_each_entry(&console_devs, console, node) {
        console_putc(console, c);
    }

    spinlock_unlock_intr_restore(&console_lock, flags);
}
