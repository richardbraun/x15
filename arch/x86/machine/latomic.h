/*
 * Copyright (c) 2018 Agustina Arzille.
 * Copyright (c) 2018 Richard Braun.
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
 * Architecture-specific definitions for local atomic operations.
 */

#ifndef X86_LATOMIC_H
#define X86_LATOMIC_H

#ifndef KERN_LATOMIC_H
#error "don't include <machine/latomic.h> directly, use <kern/latomic.h> instead"
#endif

#include <kern/atomic_types.h>
#include <kern/macros.h>

/*
 * Memory ordering is implemented with compiler barriers on entry, exit,
 * both, or neither, according to the specified ordering.
 */

#define latomic_x86_enter(memorder)                                         \
MACRO_BEGIN                                                                 \
    if ((memorder) != LATOMIC_RELAXED && (memorder) != LATOMIC_RELEASE) {   \
        barrier();                                                          \
    }                                                                       \
MACRO_END

#define latomic_x86_leave(memorder)                                         \
MACRO_BEGIN                                                                 \
    if ((memorder) != LATOMIC_RELAXED && (memorder) != LATOMIC_ACQUIRE) {   \
        barrier();                                                          \
    }                                                                       \
MACRO_END

#define latomic_x86_cas_n(ptr, oval, nval)                                  \
MACRO_BEGIN                                                                 \
    typeof(oval) prev_;                                                     \
                                                                            \
    asm volatile("cmpxchg %3, %1"                                           \
                 : "=a" (prev_), "+m" (*(ptr))                              \
                 : "0" (oval), "r" (nval));                                 \
    prev_;                                                                  \
MACRO_END

static unsigned int
latomic_x86_cas_ui(unsigned int *ptr, unsigned int oval, unsigned int nval)
{
    return latomic_x86_cas_n(ptr, oval, nval);
}

/*
 * 64-bit local atomic operations on i386 are implemented with loops using
 * the cmpxchg8b instruction. This assumes the processor is at least an i586.
 */
static unsigned long long
latomic_x86_cas_ull(unsigned long long *ptr, unsigned long long oval,
                    unsigned long long nval)
{
#ifdef __LP64__
    return latomic_x86_cas_n(ptr, oval, nval);
#else /* __LP64__ */
    asm volatile("cmpxchg8b %0"
                 : "+m" (*ptr), "+A" (oval)
                 : "b" ((unsigned long)nval),
                   "c" ((unsigned long)(nval >> 32)));
    return oval;
#endif /* __LP64__ */
}

/*
 * Helper for operations implemented with a CAS loop.
 */
#define latomic_x86_cas_loop_n(ptr, cas, op, val)                           \
MACRO_BEGIN                                                                 \
    typeof(val) prev_, oval_, nval_;                                        \
                                                                            \
    do {                                                                    \
        oval_ = *(ptr);                                                     \
        nval_ = oval_ op (val);                                             \
        prev_ = cas(ptr, oval_, nval_);                                     \
    } while (prev_ != oval_);                                               \
                                                                            \
    prev_;                                                                  \
MACRO_END


/* latomic_load */

#ifndef __LP64__
static inline unsigned long long
latomic_i386_load_64(union atomic_constptr_64 ptr, int memorder)
{
    unsigned long long prev;

    latomic_x86_enter(memorder);
    prev = latomic_x86_cas_ull((unsigned long long *)ptr.ull_ptr, 0ULL, 0ULL);
    latomic_x86_leave(memorder);

    return prev;
}
#define latomic_load_64 latomic_i386_load_64
#endif /* __LP64__ */


/* latomic_store */

#ifndef __LP64__
static inline void
latomic_i386_store_64(union atomic_ptr_64 ptr, union atomic_val_64 val,
                      int memorder)
{
    unsigned long long oval, prev;

    latomic_x86_enter(memorder);

    do {
        oval = *ptr.ull_ptr;
        prev = latomic_x86_cas_ull(ptr.ull_ptr, oval, val.ull);
    } while (prev != oval);

    latomic_x86_leave(memorder);
}
#define latomic_store_64 latomic_i386_store_64
#endif /* __LP64__ */


/* latomic_swap */

/*
 * The swap operation is implemented with the xchg instruction, which
 * implies the lock prefix. As a result, simply reuse the built-in
 * provided by the compiler.
 */

static inline unsigned int
latomic_x86_swap_32(union atomic_ptr_32 ptr, union atomic_val_32 val,
                    int memorder)
{
    return __atomic_exchange_n(ptr.ui_ptr, val.ui, memorder);
}
#define latomic_swap_32 latomic_x86_swap_32

#ifdef __LP64__
static inline unsigned long long
latomic_amd64_swap_64(union atomic_ptr_64 ptr, union atomic_val_64 val,
                      int memorder)
{
    return __atomic_exchange_n(ptr.ull_ptr, val.ull, memorder);
}
#define latomic_swap_64 latomic_amd64_swap_64
#else /* __LP64__ */
static inline unsigned long long
latomic_i386_swap_64(union atomic_ptr_64 ptr, union atomic_val_64 val,
                     int memorder)
{
    unsigned long long oval, prev;

    latomic_x86_enter(memorder);

    do {
        oval = *ptr.ull_ptr;
        prev = latomic_x86_cas_ull(ptr.ull_ptr, oval, val.ull);
    } while (prev != oval);

    latomic_x86_leave(memorder);

    return prev;
}
#define latomic_swap_64 latomic_i386_swap_64
#endif /* __LP64__ */


/* latomic_cas */

static inline unsigned int
latomic_x86_cas_32(union atomic_ptr_32 ptr, union atomic_val_32 oval,
                   union atomic_val_32 nval, int memorder)
{
    unsigned int prev;

    latomic_x86_enter(memorder);
    prev = latomic_x86_cas_ui(ptr.ui_ptr, oval.ui, nval.ui);
    latomic_x86_leave(memorder);

    return prev;
}
#define latomic_cas_32 latomic_x86_cas_32

static inline unsigned long long
latomic_x86_cas_64(union atomic_ptr_64 ptr, union atomic_val_64 oval,
                   union atomic_val_64 nval, int memorder)
{
    unsigned long long prev;

    latomic_x86_enter(memorder);
    prev = latomic_x86_cas_ull(ptr.ull_ptr, oval.ull, nval.ull);
    latomic_x86_leave(memorder);

    return prev;
}
#define latomic_cas_64 latomic_x86_cas_64


/* latomic_fetch_add */

/*
 * The fetch_add and fetch_sub operations are the only fetch_xxx operations
 * that may not be implemented with a CAS loop, but with the xadd instruction
 * instead.
 */

#define latomic_x86_fetch_add_n(ptr, val)                                   \
MACRO_BEGIN                                                                 \
   typeof(val) prev_;                                                       \
                                                                            \
   asm volatile("xadd %0, %1"                                               \
                : "=r" (prev_), "+m" (*(ptr))                               \
                : "0" (val));                                               \
   prev_;                                                                   \
MACRO_END

static inline unsigned int
latomic_x86_fetch_add_32(union atomic_ptr_32 ptr, union atomic_val_32 val,
                         int memorder)
{
    unsigned int prev;

    latomic_x86_enter(memorder);
    prev = latomic_x86_fetch_add_n(ptr.ui_ptr, val.ui);
    latomic_x86_leave(memorder);

    return prev;
}
#define latomic_fetch_add_32 latomic_x86_fetch_add_32

#ifdef __LP64__
static inline unsigned long long
latomic_amd64_fetch_add_64(union atomic_ptr_64 ptr, union atomic_val_64 val,
                           int memorder)
{
    unsigned long long prev;

    latomic_x86_enter(memorder);
    prev = latomic_x86_fetch_add_n(ptr.ull_ptr, val.ull);
    latomic_x86_leave(memorder);

    return prev;
}
#define latomic_fetch_add_64 latomic_amd64_fetch_add_64
#else /* __LP64__ */
static inline unsigned long long
latomic_i386_fetch_add_64(union atomic_ptr_64 ptr, union atomic_val_64 val,
                          int memorder)
{
    unsigned long long prev;

    latomic_x86_enter(memorder);
    prev = latomic_x86_cas_loop_n(ptr.ull_ptr, latomic_x86_cas_ull, +, val.ull);
    latomic_x86_leave(memorder);

    return prev;
}
#define latomic_fetch_add_64 latomic_i386_fetch_add_64
#endif /* __LP64__ */


/* latomic_fetch_sub */

static inline unsigned int
latomic_x86_fetch_sub_32(union atomic_ptr_32 ptr, union atomic_val_32 val,
                         int memorder)
{
    unsigned int prev;

    latomic_x86_enter(memorder);
    prev = latomic_x86_fetch_add_n(ptr.ui_ptr, -val.ui);
    latomic_x86_leave(memorder);

    return prev;
}
#define latomic_fetch_sub_32 latomic_x86_fetch_sub_32

#ifdef __LP64__
static inline unsigned long long
latomic_amd64_fetch_sub_64(union atomic_ptr_64 ptr, union atomic_val_64 val,
                           int memorder)
{
    unsigned long long prev;

    latomic_x86_enter(memorder);
    prev = latomic_x86_fetch_add_n(ptr.ull_ptr, -val.ull);
    latomic_x86_leave(memorder);

    return prev;
}
#define latomic_fetch_sub_64 latomic_amd64_fetch_sub_64
#else /* __LP64__ */
static inline unsigned long long
latomic_i386_fetch_sub_64(union atomic_ptr_64 ptr, union atomic_val_64 val,
                          int memorder)
{
    unsigned long long prev;

    latomic_x86_enter(memorder);
    prev = latomic_x86_cas_loop_n(ptr.ull_ptr, latomic_x86_cas_ull, -, val.ull);
    latomic_x86_leave(memorder);

    return prev;
}
#define latomic_fetch_sub_64 latomic_i386_fetch_sub_64
#endif /* __LP64__ */


/* latomic_fetch_and */

static inline unsigned int
latomic_x86_fetch_and_32(union atomic_ptr_32 ptr, union atomic_val_32 val,
                         int memorder)
{
    unsigned int prev;

    latomic_x86_enter(memorder);
    prev = latomic_x86_cas_loop_n(ptr.ui_ptr, latomic_x86_cas_ui, &, val.ui);
    latomic_x86_leave(memorder);

    return prev;
}
#define latomic_fetch_and_32 latomic_x86_fetch_and_32

static inline unsigned long long
latomic_x86_fetch_and_64(union atomic_ptr_64 ptr, union atomic_val_64 val,
                         int memorder)
{
    unsigned long long prev;

    latomic_x86_enter(memorder);
    prev = latomic_x86_cas_loop_n(ptr.ull_ptr, latomic_x86_cas_ull, &, val.ull);
    latomic_x86_leave(memorder);

    return prev;
}
#define latomic_fetch_and_64 latomic_x86_fetch_and_64


/* latomic_fetch_or */

static inline unsigned int
latomic_x86_fetch_or_32(union atomic_ptr_32 ptr, union atomic_val_32 val,
                        int memorder)
{
    unsigned int prev;

    latomic_x86_enter(memorder);
    prev = latomic_x86_cas_loop_n(ptr.ui_ptr, latomic_x86_cas_ui, |, val.ui);
    latomic_x86_leave(memorder);

    return prev;
}
#define latomic_fetch_or_32 latomic_x86_fetch_or_32

static inline unsigned long long
latomic_x86_fetch_or_64(union atomic_ptr_64 ptr, union atomic_val_64 val,
                        int memorder)
{
    unsigned long long prev;

    latomic_x86_enter(memorder);
    prev = latomic_x86_cas_loop_n(ptr.ull_ptr, latomic_x86_cas_ull, |, val.ull);
    latomic_x86_leave(memorder);

    return prev;
}
#define latomic_fetch_or_64 latomic_x86_fetch_or_64


/* latomic_fetch_xor */

static inline unsigned int
latomic_x86_fetch_xor_32(union atomic_ptr_32 ptr, union atomic_val_32 val,
                         int memorder)
{
    unsigned int prev;

    latomic_x86_enter(memorder);
    prev = latomic_x86_cas_loop_n(ptr.ui_ptr, latomic_x86_cas_ui, ^, val.ui);
    latomic_x86_leave(memorder);

    return prev;
}
#define latomic_fetch_xor_32 latomic_x86_fetch_xor_32

static inline unsigned long long
latomic_x86_fetch_xor_64(union atomic_ptr_64 ptr, union atomic_val_64 val,
                         int memorder)
{
    unsigned long long prev;

    latomic_x86_enter(memorder);
    prev = latomic_x86_cas_loop_n(ptr.ull_ptr, latomic_x86_cas_ull, ^, val.ull);
    latomic_x86_leave(memorder);

    return prev;
}
#define latomic_fetch_xor_64 latomic_x86_fetch_xor_64


/* latomic_add */

#define latomic_x86_add_n(ptr, val, suffix)                                 \
MACRO_BEGIN                                                                 \
    asm volatile("add" suffix " %1, %0"                                     \
                 : "+m" (*(ptr))                                            \
                 : "ir" (val));                                             \
MACRO_END

static inline void
latomic_x86_add_32(union atomic_ptr_32 ptr, union atomic_val_32 val,
                   int memorder)
{
    latomic_x86_enter(memorder);
    latomic_x86_add_n(ptr.ui_ptr, val.ui, "l");
    latomic_x86_leave(memorder);
}
#define latomic_add_32 latomic_x86_add_32

#ifdef __LP64__
static inline void
latomic_amd64_add_64(union atomic_ptr_64 ptr, union atomic_val_64 val,
                     int memorder)
{
    latomic_x86_enter(memorder);
    latomic_x86_add_n(ptr.ull_ptr, val.ull, "q");
    latomic_x86_leave(memorder);
}
#define latomic_add_64 latomic_amd64_add_64
#else /* __LP64__ */
static inline void
latomic_i386_add_64(union atomic_ptr_64 ptr, union atomic_val_64 val,
                    int memorder)
{
    latomic_fetch_add_64(ptr, val, memorder);
}
#define latomic_add_64 latomic_i386_add_64
#endif /* __LP64__ */


/* latomic_sub */

static inline void
latomic_x86_sub_32(union atomic_ptr_32 ptr, union atomic_val_32 val,
                   int memorder)
{
    latomic_x86_enter(memorder);
    latomic_x86_add_n(ptr.ui_ptr, -val.ui, "l");
    latomic_x86_leave(memorder);
}
#define latomic_sub_32 latomic_x86_sub_32

#ifdef __LP64__
static inline void
latomic_amd64_sub_64(union atomic_ptr_64 ptr, union atomic_val_64 val,
                     int memorder)
{
    latomic_x86_enter(memorder);
    latomic_x86_add_n(ptr.ull_ptr, -val.ull, "q");
    latomic_x86_leave(memorder);
}
#define latomic_sub_64 latomic_amd64_sub_64
#else /* __LP64__ */
static inline void
latomic_i386_sub_64(union atomic_ptr_64 ptr, union atomic_val_64 val,
                    int memorder)
{
    latomic_fetch_sub_64(ptr, val, memorder);
}
#define latomic_sub_64 latomic_i386_sub_64
#endif /* __LP64__ */


/* latomic_and */

#define latomic_x86_and_n(ptr, val, suffix)                                 \
MACRO_BEGIN                                                                 \
    asm volatile("and" suffix " %1, %0"                                     \
                 : "+m" (*(ptr))                                            \
                 : "ir" (val));                                             \
MACRO_END

static inline void
latomic_x86_and_32(union atomic_ptr_32 ptr, union atomic_val_32 val,
                   int memorder)
{
    latomic_x86_enter(memorder);
    latomic_x86_and_n(ptr.ui_ptr, val.ui, "l");
    latomic_x86_leave(memorder);
}
#define latomic_and_32 latomic_x86_and_32

#ifdef __LP64__
static inline void
latomic_amd64_and_64(union atomic_ptr_64 ptr, union atomic_val_64 val,
                     int memorder)
{
    latomic_x86_enter(memorder);
    latomic_x86_and_n(ptr.ull_ptr, val.ull, "q");
    latomic_x86_leave(memorder);
}
#define latomic_and_64 latomic_amd64_and_64
#else /* __LP64__ */
static inline void
latomic_i386_and_64(union atomic_ptr_64 ptr, union atomic_val_64 val,
                    int memorder)
{
    latomic_fetch_and_64(ptr, val, memorder);
}
#define latomic_and_64 latomic_i386_and_64
#endif /* __LP64__ */


/* latomic_or */

#define latomic_x86_or_n(ptr, val, suffix)                                  \
MACRO_BEGIN                                                                 \
    asm volatile("or" suffix " %1, %0"                                      \
                 : "+m" (*(ptr))                                            \
                 : "ir" (val));                                             \
MACRO_END

static inline void
latomic_x86_or_32(union atomic_ptr_32 ptr, union atomic_val_32 val,
                  int memorder)
{
    latomic_x86_enter(memorder);
    latomic_x86_or_n(ptr.ui_ptr, val.ui, "l");
    latomic_x86_leave(memorder);
}
#define latomic_or_32 latomic_x86_or_32

#ifdef __LP64__
static inline void
latomic_amd64_or_64(union atomic_ptr_64 ptr, union atomic_val_64 val,
                    int memorder)
{
    latomic_x86_enter(memorder);
    latomic_x86_or_n(ptr.ull_ptr, val.ull, "q");
    latomic_x86_leave(memorder);
}
#define latomic_or_64 latomic_amd64_or_64
#else /* __LP64__ */
static inline void
latomic_i386_or_64(union atomic_ptr_64 ptr, union atomic_val_64 val,
                   int memorder)
{
    latomic_fetch_or_64(ptr, val, memorder);
}
#define latomic_or_64 latomic_i386_or_64
#endif /* __LP64__ */


/* latomic_xor */

#define latomic_x86_xor_n(ptr, val, suffix)                                 \
MACRO_BEGIN                                                                 \
    asm volatile("xor" suffix " %1, %0"                                     \
                 : "+m" (*(ptr))                                            \
                 : "ir" (val));                                             \
MACRO_END

static inline void
latomic_x86_xor_32(union atomic_ptr_32 ptr, union atomic_val_32 val,
                   int memorder)
{
    latomic_x86_enter(memorder);
    latomic_x86_xor_n(ptr.ui_ptr, val.ui, "l");
    latomic_x86_leave(memorder);
}
#define latomic_xor_32 latomic_x86_xor_32

#ifdef __LP64__
static inline void
latomic_amd64_xor_64(union atomic_ptr_64 ptr, union atomic_val_64 val,
                     int memorder)
{
    latomic_x86_enter(memorder);
    latomic_x86_xor_n(ptr.ull_ptr, val.ull, "q");
    latomic_x86_leave(memorder);
}
#define latomic_xor_64 latomic_amd64_xor_64
#else /* __LP64__ */
static inline void
latomic_i386_xor_64(union atomic_ptr_64 ptr, union atomic_val_64 val,
                    int memorder)
{
    latomic_fetch_xor_64(ptr, val, memorder);
}
#define latomic_xor_64 latomic_i386_xor_64
#endif /* __LP64__ */

#endif /* X86_LATOMIC_H */
