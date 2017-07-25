/*
 * Copyright (c) 2010-2017 Richard Braun.
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
 * The functions provided by this module implement a subset of the standard
 * sprintf- and sscanf-like functions.
 *
 * sprintf:
 *  - flags: # 0 - ' ' (space) +
 *  - field width is supported
 *  - precision is supported
 *
 * sscanf:
 *  - flags: *
 *  - field width is supported
 *
 * common:
 *  - modifiers: hh h l ll z t
 *  - specifiers: d i o u x X c s p n %
 *
 *
 * Upstream site with license notes :
 * http://git.sceen.net/rbraun/librbraun.git/
 */

#ifndef _FMT_H
#define _FMT_H

#include <stdarg.h>
#include <stddef.h>

int fmt_sprintf(char *str, const char *format, ...)
    __attribute__((format(printf, 2, 3)));

int fmt_vsprintf(char *str, const char *format, va_list ap)
    __attribute__((format(printf, 2, 0)));

int fmt_snprintf(char *str, size_t size, const char *format, ...)
    __attribute__((format(printf, 3, 4)));

int fmt_vsnprintf(char *str, size_t size, const char *format, va_list ap)
    __attribute__((format(printf, 3, 0)));

int fmt_sscanf(const char *str, const char *format, ...)
    __attribute__((format(scanf, 2, 3)));

int fmt_vsscanf(const char *str, const char *format, va_list ap)
    __attribute__((format(scanf, 2, 0)));

#endif /* _FMT_H */
