/*
 * Copyright (c) 2010, 2012, 2013 Richard Braun.
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

#include <kern/spinlock.h>
#include <machine/cpu.h>

/*
 * Size of the static buffer.
 */
#define PRINTK_BUFSIZE 1024

/*
 * XXX Must be provided by a console driver.
 */
extern void console_write_byte(char c);

static char printf_buffer[PRINTK_BUFSIZE];
static struct spinlock printf_lock;

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
    char *ptr;

    spinlock_lock_intr_save(&printf_lock, &flags);

    length = vsnprintf(printf_buffer, sizeof(printf_buffer), format, ap);

    for (ptr = printf_buffer; *ptr != '\0'; ptr++) {
        console_write_byte(*ptr);
    }

    spinlock_unlock_intr_restore(&printf_lock, flags);

    return length;
}

void
printf_setup(void)
{
    spinlock_init(&printf_lock);
}
