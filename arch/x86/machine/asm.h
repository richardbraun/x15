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

#include <machine/param.h>

#ifdef __ASSEMBLY__

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
.size x, . - x;     \
x ## _end:

#ifdef __LP64__
#define ASM_IRET iretq
#else /* __LP64__ */
#define ASM_IRET iret
#endif /* __LP64__ */

#endif /* __ASSEMBLY__ */

#endif /* _X86_ASM_H */
