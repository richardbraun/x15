/*
 * Copyright (c) 2009-2018 Richard Braun.
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
 * Upstream site with license notes :
 * http://git.sceen.net/rbraun/librbraun.git/
 *
 *
 * Helper macros.
 *
 * This file is a top header in the inclusion hierarchy, and shouldn't include
 * other headers that may cause circular dependencies.
 *
 * TODO Improve documentation.
 */

#ifndef KERN_MACROS_H
#define KERN_MACROS_H

#if !defined(__GNUC__) || (__GNUC__ < 4)
#error "GCC 4+ required"
#endif

#ifndef __ASSEMBLER__
#include <stddef.h>
#endif

/*
 * Attributes for variables that are mostly read and seldom changed.
 */
#define __read_mostly       __section(".data.read_mostly")

#define MACRO_BEGIN         ({
#define MACRO_END           })

#define __QUOTE(x)          #x
#define QUOTE(x)            __QUOTE(x)

#ifdef __ASSEMBLER__
#define DECL_CONST(x, s)    x
#else /* __ASSEMBLER__ */
#define __DECL_CONST(x, s)  x##s
#define DECL_CONST(x, s)    __DECL_CONST(x, s)
#endif /* __ASSEMBLER__ */

#define STRLEN(x)           (sizeof(x) - 1)
#define ARRAY_SIZE(x)       (sizeof(x) / sizeof((x)[0]))

#define MIN(a, b)           ((a) < (b) ? (a) : (b))
#define MAX(a, b)           ((a) > (b) ? (a) : (b))

#define DIV_CEIL(n, d)      (((n) + (d) - 1) / (d))

#define P2ALIGNED(x, a)     (((x) & ((a) - 1)) == 0)
#define ISP2(x)             P2ALIGNED(x, x)
#define P2ALIGN(x, a)       ((x) & -(a))        /* decreases if not aligned */
#define P2ROUND(x, a)       (-(-(x) & -(a)))    /* increases if not aligned */
#define P2END(x, a)         (-(~(x) & -(a)))    /* always increases */

#define structof(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))

#define likely(expr)        __builtin_expect(!!(expr), 1)
#define unlikely(expr)      __builtin_expect(!!(expr), 0)

#define barrier()           asm volatile("" : : : "memory")

/*
 * The following macros may be provided by the C environment.
 */

#ifndef __noinline
#define __noinline          __attribute__((noinline))
#endif

#ifndef __always_inline
#define __always_inline     inline __attribute__((always_inline))
#endif

#ifndef __section
#define __section(x)        __attribute__((section(x)))
#endif

#ifndef __packed
#define __packed            __attribute__((packed))
#endif

#ifndef __unused
#define __unused            __attribute__((unused))
#endif

#ifndef __used
#define __used              __attribute__((used))
#endif

#ifndef __fallthrough
#if __GNUC__ >= 7
#define __fallthrough       __attribute__((fallthrough))
#else /* __GNUC__ >= 7 */
#define __fallthrough
#endif /* __GNUC__ >= 7 */
#endif

#endif /* KERN_MACROS_H */
