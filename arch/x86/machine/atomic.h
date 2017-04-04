/*
 * Copyright (c) 2012-2017 Richard Braun.
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
 * Architecture-specific atomic operations and definitions.
 *
 */

#ifndef _X86_ATOMIC_H
#define _X86_ATOMIC_H

#ifdef __LP64__

#define atomic_load(ptr, mo)         __atomic_load_n((ptr), mo)
#define atomic_store(ptr, val, mo)   __atomic_store_n((ptr), (val), mo)

#else /* __LP64__ */

/*
 * On x86, the compiler generates either an FP-stack read/write, or an SSE2
 * store/load to implement these 64-bit atomic operations. Since that's not
 * feasible on kernel-land, we fallback to cmpxchg8b. Note that this means
 * that 'atomic_load' cannot be used on a const pointer. However, if it's
 * being accessed by an atomic operation, then it's very likely that it can
 * also be modified, so it should be OK.
 */

#define atomic_load(ptr, mo)                                              \
MACRO_BEGIN                                                               \
    typeof(*(ptr)) ___ret;                                                \
                                                                          \
    if (sizeof(___ret) != 8) {                                            \
        ___ret = __atomic_load_n((ptr), mo);                              \
    } else {                                                              \
        ___ret = 0;                                                       \
        __atomic_compare_exchange_n((uint64_t *)(ptr), &___ret, ___ret,   \
                                    0, mo, __ATOMIC_RELAXED);             \
    }                                                                     \
                                                                          \
    ___ret;                                                               \
MACRO_END

#define atomic_store(ptr, val, mo)                                        \
MACRO_BEGIN                                                               \
    if (sizeof(*(ptr) != 8)) {                                            \
        __atomic_store_n((ptr), (val), mo);                               \
    } else {                                                              \
        typeof(ptr) ___ptr;                                               \
        typeof(val) ___val, ___exp;                                       \
                                                                          \
        ___ptr = (uint64_t *)(ptr);                                       \
        ___val = (val);                                                   \
        ___exp = *___ptr;                                                 \
                                                                          \
        while (!__atomic_compare_exchange_n(___ptr, &___exp, ___val, 0,   \
               momo, __ATOMIC_RELAXED)) {                                 \
        }                                                                 \
                                                                          \
    }                                                                     \
MACRO_END

#endif /* __LP64__ */

/* Notify the generic header that we implemented loads and stores */
#define ATOMIC_LOAD_DEFINED
#define ATOMIC_STORE_DEFINED

/* Both x86 and x86_64 can use atomic operations on 64-bit values */
#define ATOMIC_HAVE_64B_OPS

#endif /* _X86_ATOMIC_H */
