/*
 * Copyright (c) 2011, 2012 Richard Braun.
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

#ifndef _X86_ASM_H
#define _X86_ASM_H

#ifndef __ASSEMBLER__
#warning "asm.h included from a C file"
#endif /* __ASSEMBLER__ */

#include <machine/param.h>

#define ASM_ENTRY(x)    \
.align TEXT_ALIGN;      \
.global x;              \
.type x, STT_FUNC;      \
x:

#define ASM_DATA(x)     \
.align DATA_ALIGN;      \
.global x;              \
.type x, STT_OBJECT;    \
x:

#define ASM_END(x)  \
.size x, . - x

#endif /* _X86_ASM_H */
