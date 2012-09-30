/*
 * Copyright (c) 2010, 2011 Richard Braun.
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

#ifndef _LIB_STDDEF_H
#define _LIB_STDDEF_H

#define NULL ((void *)0)

#define offsetof(type, member) __builtin_offsetof(type, member)

#ifdef __LP64__
typedef unsigned long size_t;
typedef long ssize_t;
typedef long ptrdiff_t;
#else /* __LP64__ */
typedef unsigned int size_t;
typedef int ssize_t;
typedef int ptrdiff_t;
#endif /* __LP64__ */

#endif /* _LIB_STDDEF_H */
