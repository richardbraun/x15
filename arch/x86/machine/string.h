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

#ifndef _X86_STRING_H
#define _X86_STRING_H

/*
 * Provide architecture-specific string functions.
 */
#define STRING_ARCH_MEMCPY
#define STRING_ARCH_MEMMOVE
#define STRING_ARCH_MEMSET
#define STRING_ARCH_MEMCMP
#define STRING_ARCH_STRLEN
#define STRING_ARCH_STRCPY
#define STRING_ARCH_STRCMP
#define STRING_ARCH_STRNCMP
#define STRING_ARCH_STRCHR

#endif /* _X86_STRING_H */
