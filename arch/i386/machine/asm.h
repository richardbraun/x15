/*
 * Copyright (c) 2011 Richard Braun.
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

#ifndef _I386_ASM_H
#define _I386_ASM_H

#ifdef __ASSEMBLY__

#define TEXT_ALIGN  4
#define DATA_ALIGN  2

#define ENTRY(x)            \
.p2align TEXT_ALIGN, 0x90;  \
.global x;                  \
.type x, STT_FUNC;          \
x:

#define DATA(x)         \
.p2align DATA_ALIGN;    \
.global x;              \
.type x, STT_OBJECT;    \
x:

#define END(x) .size x, . - x;

#endif /* __ASSEMBLY__ */

#endif /* _I386_ASM_H */
