/*
 * Copyright (c) 2010-2019 Richard Braun.
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

#include <stdio.h>

#include <kern/console.h>
#include <kern/fmt.h>
#include <kern/init.h>
#include <kern/spinlock.h>
#include <machine/boot.h>
#include <machine/cpu.h>

/*
 * Size of the static buffer.
 */
#define PRINTF_BUFSIZE 1024

static char printf_buffer[PRINTF_BUFSIZE];
static struct spinlock printf_lock;

static int
vprintf_common(const char *format, va_list ap)
{
    int length;

    length = fmt_vsnprintf(printf_buffer, sizeof(printf_buffer), format, ap);

    for (char *ptr = printf_buffer; *ptr != '\0'; ptr++) {
        console_putchar(*ptr);
    }

    return length;
}

int
printf(const char *format, ...)
{
    va_list ap;
    int length;

    va_start(ap, format);
    length = vprintf(format, ap);
    va_end(ap);

    return length;
}

int
vprintf(const char *format, va_list ap)
{
    unsigned long flags;
    int length;

    spinlock_lock_intr_save(&printf_lock, &flags);
    length = vprintf_common(format, ap);
    spinlock_unlock_intr_restore(&printf_lock, flags);

    return length;
}

int
printf_ln(const char *format, ...)
{
    va_list ap;
    int length;

    va_start(ap, format);
    length = vprintf_ln(format, ap);
    va_end(ap);

    return length;
}

int
vprintf_ln(const char *format, va_list ap)
{
    unsigned long flags;
    int length;

    spinlock_lock_intr_save(&printf_lock, &flags);
    length = vprintf_common(format, ap);
    console_putchar('\n');
    spinlock_unlock_intr_restore(&printf_lock, flags);

    return length;
}

static int __init
printf_setup(void)
{
    spinlock_init(&printf_lock);
    return 0;
}

INIT_OP_DEFINE(printf_setup,
               INIT_OP_DEP(boot_bootstrap_console, true),
               INIT_OP_DEP(console_bootstrap, true),
               INIT_OP_DEP(spinlock_setup, true));
