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

#ifndef _STDIO_H
#define _STDIO_H

#include <kern/fmt.h>
#include <kern/printf.h>

#ifndef EOF
#define EOF (-1)
#endif

void console_putchar(char c);
char console_getchar(void);

#define getchar console_getchar
#define putchar console_putchar

#define sprintf     fmt_sprintf
#define snprintf    fmt_snprintf
#define vsprintf    fmt_vsprintf
#define vsnprintf   fmt_vsnprintf

#define sscanf      fmt_sscanf
#define vsscanf     fmt_vsscanf

#endif /* _STDIO_H */
