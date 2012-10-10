/*
 * Copyright (c) 2009, 2010 Richard Braun.
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
 * Helper macros.
 */

#ifndef _LIB_MACROS_H
#define _LIB_MACROS_H

#ifndef __ASSEMBLY__
#include <lib/stddef.h>
#endif /* __ASSEMBLY__ */

#define MACRO_BEGIN         ({
#define MACRO_END           })

#define XQUOTE(x)           #x
#define QUOTE(x)            XQUOTE(x)

#ifdef __ASSEMBLY__
#define DECL_CONST(x, s)    x
#else /* __ASSEMBLY__ */
#define __DECL_CONST(x, s)  x##s
#define DECL_CONST(x, s)    __DECL_CONST(x, s)
#endif /* __ASSEMBLY__ */

#define STRLEN(x)           (sizeof(x) - 1)
#define ARRAY_SIZE(x)       (sizeof(x) / sizeof((x)[0]))

#define MIN(a, b)           ((a) < (b) ? (a) : (b))
#define MAX(a, b)           ((a) > (b) ? (a) : (b))

#define P2ALIGNED(x, a)     (((x) & ((a) - 1)) == 0)
#define ISP2(x)             P2ALIGNED(x, x)
#define P2ALIGN(x, a)       ((x) & -(a))
#define P2ROUND(x, a)       (-(-(x) & -(a)))
#define P2END(x, a)         (-(~(x) & -(a)))

#define structof(ptr, type, member) \
    ((type *)((char *)ptr - offsetof(type, member)))

#define alignof(x)          __alignof__(x)

#define likely(expr)        __builtin_expect(!!(expr), 1)
#define unlikely(expr)      __builtin_expect(!!(expr), 0)

#define barrier()           asm volatile("" : : : "memory")

#define __noreturn          __attribute__((noreturn))
#define __aligned(x)        __attribute__((aligned(x)))
#define __always_inline     inline __attribute__((always_inline))
#define __section(x)        __attribute__((section(x)))
#define __packed            __attribute__((packed))
#define __alias(x)          __attribute__((alias(x)))

#define __format_printf(fmt, args) \
    __attribute__((format(printf, fmt, args)))

#endif /* _LIB_MACROS_H */
