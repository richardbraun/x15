/*
 * Copyright (c) 2010, 2012 Richard Braun.
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

#include <kern/printk.h>
#include <kern/spinlock.h>
#include <kern/sprintf.h>

/*
 * Size of the static buffer.
 */
#define PRINTK_BUFSIZE 1024

/*
 * XXX Must be provided by a console driver.
 */
extern void console_write_byte(char c);

static char printk_buffer[PRINTK_BUFSIZE];
static struct spinlock printk_lock = SPINLOCK_INITIALIZER;

int
printk(const char *format, ...)
{
    va_list ap;
    int length;

    va_start(ap, format);
    length = vprintk(format, ap);
    va_end(ap);

    return length;
}

int
vprintk(const char *format, va_list ap)
{
    unsigned long flags;
    int length;
    char *ptr;

    flags = spinlock_lock(&printk_lock);

    length = vsnprintf(printk_buffer, sizeof(printk_buffer), format, ap);

    for (ptr = printk_buffer; *ptr != '\0'; ptr++)
        console_write_byte(*ptr);

    spinlock_unlock(&printk_lock, flags);

    return length;
}
