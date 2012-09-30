/*
 * Copyright (c) 2010 Richard Braun.
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
 * Formatted output functions.
 *
 * The printk() and vprintk() functions internally use a statically
 * allocated buffer. They won't produce output larger than 1 KiB. They can
 * be used safely in any context.
 *
 * See the sprintf library module for information about the supported formats.
 */

#ifndef _KERN_PRINTK_H
#define _KERN_PRINTK_H

#include <stdarg.h>

#include <lib/macros.h>

int printk(const char *format, ...) __format_printf(1, 2);
int vprintk(const char *format, va_list ap) __format_printf(1, 0);

#endif /* _KERN_PRINTK_H */
