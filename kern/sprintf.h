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
 * Formatted string functions.
 *
 * The functions provided by this module implement a subset of the C99
 * sprintf() like functions, mostly centered around character, string, and
 * integer conversions.
 *
 * The supported specifiers are: d i o u x X c s p n %
 * The supported length modifiers are: hh h l ll z t
 */

#ifndef _KERN_SPRINTF_H
#define _KERN_SPRINTF_H

#ifndef _STDIO_H
#error "do not use <kern/sprintf.h> directly; include <stdio.h> instead"
#endif /* _STDIO_H */

#include <stdarg.h>

#include <kern/macros.h>

int sprintf(char *str, const char *format, ...) __format_printf(2, 3);
int vsprintf(char *str, const char *format, va_list ap) __format_printf(2, 0);

int snprintf(char *str, size_t size, const char *format, ...)
    __format_printf(3, 4);
int vsnprintf(char *str, size_t size, const char *format, va_list ap)
    __format_printf(3, 0);

#endif /* _KERN_SPRINTF_H */
