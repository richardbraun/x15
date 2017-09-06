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
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include <kern/arg.h>
#include <kern/error.h>
#include <kern/init.h>
#include <kern/console.h>
#include <kern/list.h>
#include <kern/log.h>
#include <kern/mutex.h>
#include <kern/spinlock.h>
#include <kern/thread.h>
#include <machine/boot.h>
#include <machine/cpu.h>

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
             const struct console_ops *ops)
{
    assert(ops != NULL);

    spinlock_init(&console->lock);
    console->ops = ops;
    cbuf_init(&console->recvbuf, console->buffer, sizeof(console->buffer));
    console->waiter = NULL;
    strlcpy(console->name, name, sizeof(console->name));
}

static int
console_process_ctrl_char(struct console *console, char c)
{
    switch (c) {
    case CONSOLE_SCROLL_UP:
    case CONSOLE_SCROLL_DOWN:
        break;
    default:
        return ERROR_INVAL;
    }

    console->ops->putc(console, c);
    return 0;
}

static void
console_putc(struct console *console, char c)
{
    unsigned long flags;

    spinlock_lock_intr_save(&console->lock, &flags);
    console->ops->putc(console, c);
    spinlock_unlock_intr_restore(&console->lock, flags);
}

static char
console_getc(struct console *console)
{
    unsigned long flags;
    int error;
    char c;

    spinlock_lock_intr_save(&console->lock, &flags);

    if (console->waiter != NULL) {
        c = EOF;
        goto out;
    }

    console->waiter = thread_self();

    for (;;) {
        error = cbuf_popb(&console->recvbuf, &c);

        if (!error) {
            error = console_process_ctrl_char(console, c);

            if (error) {
                break;
            }
        }

        thread_sleep(&console->lock, console, "consgetc");
    }

    console->waiter = NULL;

out:
    spinlock_unlock_intr_restore(&console->lock, flags);

    return c;
}

static int __init
console_bootstrap(void)
{
    list_init(&console_devs);
    console_name = arg_value("console");
    return 0;
}

INIT_OP_DEFINE(console_bootstrap,
               INIT_OP_DEP(arg_setup, true),
               INIT_OP_DEP(log_setup, true));

static int __init
console_setup(void)
{
    return 0;
}

INIT_OP_DEFINE(console_setup,
               INIT_OP_DEP(boot_setup_console, true),
               INIT_OP_DEP(thread_setup, true));

void __init
console_register(struct console *console)
{
    assert(console->ops != NULL);

    list_insert_tail(&console_devs, &console->node);

    if ((console_dev == NULL) && console_name_match(console->name)) {
        console_dev = console;
    }

    log_info("console: %s registered", console->name);

    if (console == console_dev) {
        log_info("console: %s selected as active console", console->name);
    }
}

void
console_intr(struct console *console, const char *s)
{
    assert(thread_check_intr_context());

    if (*s == '\0') {
        return;
    }

    spinlock_lock(&console->lock);

    while (*s != '\0') {
        if (cbuf_size(&console->recvbuf) == cbuf_capacity(&console->recvbuf)) {
            goto out;
        }

        cbuf_pushb(&console->recvbuf, *s, false);
        s++;
    }

    thread_wakeup(console->waiter);

out:
    spinlock_unlock(&console->lock);
}

void
console_putchar(char c)
{
    if (console_dev == NULL) {
        return;
    }

    console_putc(console_dev, c);
}

char
console_getchar(void)
{
    char c;

    if (console_dev == NULL) {
        c = EOF;
        goto out;
    }

    c = console_getc(console_dev);

out:
    return c;
}
