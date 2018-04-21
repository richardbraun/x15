/*
 * Copyright (c) 2012-2018 Richard Braun.
 * Copyright (c) 2017 Agustina Arzille.
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
 * Architecture-specific definitions for atomic operations.
 */

#ifndef X86_ATOMIC_H
#define X86_ATOMIC_H

#ifndef KERN_ATOMIC_H
#error "don't include <machine/atomic.h> directly, use <kern/atomic.h> instead"
#endif

#include <stdbool.h>

#include <kern/macros.h>

#ifndef __LP64__

/*
 * XXX Clang seems to have trouble with 64-bit operations on 32-bit
 * processors.
 */
#ifndef __clang__

/* Report that 64-bits operations are supported */
#define ATOMIC_HAVE_64B_OPS

/*
 * On i386, the compiler generates either an FP-stack read/write, or an SSE2
 * store/load to implement these 64-bit atomic operations. Since that's not
 * feasible in the kernel, fall back to cmpxchg8b.
 *
 * XXX Note that, in this case, loading becomes a potentially mutating
 * operation, but it's not expected to be a problem since atomic operations
 * are normally not used on read-only memory.
 *
 * Also note that this assumes the processor is at least an i586.
 */

#define atomic_x86_select(ptr, op)                      \
_Generic(*(ptr),                                        \
    unsigned int: __atomic_ ## op ## _n,                \
    unsigned long long: atomic_i386_ ## op ## _64)

static inline unsigned long long
atomic_i386_load_64(const unsigned long long *ptr, int memorder)
{
    unsigned long long prev;

    prev = 0;
    __atomic_compare_exchange_n((unsigned long long *)ptr, &prev,
                                0, false, memorder, __ATOMIC_RELAXED);
    return prev;
}

#define atomic_load_n(ptr, memorder) \
atomic_x86_select(ptr, load)(ptr, memorder)

static inline void
atomic_i386_store_64(unsigned long long *ptr, unsigned long long val,
                     int memorder)
{
    unsigned long long prev;
    bool done;

    prev = *ptr;

    do {
        done = __atomic_compare_exchange_n(ptr, &prev, val,
                                           false, memorder,
                                           __ATOMIC_RELAXED);
    } while (!done);
}

#define atomic_store_n(ptr, val, memorder) \
atomic_x86_select(ptr, store)(ptr, val, memorder)

#endif /* __clang__ */

#else /* __LP64__ */

/* Report that 64-bits operations are supported */
#define ATOMIC_HAVE_64B_OPS

#endif /* __LP64__ */

#endif /* X86_ATOMIC_H */
