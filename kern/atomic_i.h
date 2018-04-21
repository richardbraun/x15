/*
 * Copyright (c) 2018 Richard Braun.
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
 * Architecture-specific code may override any of the type-generic
 * atomic_xxx_n macros by defining them.
 */

#ifndef KERN_ATOMIC_I_H
#define KERN_ATOMIC_I_H

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>

#include <kern/macros.h>
#include <machine/atomic.h>

#ifndef atomic_load_n
#define atomic_load_n __atomic_load_n
#endif /* atomic_load_n */

#ifndef atomic_store_n
#define atomic_store_n __atomic_store_n
#endif /* atomic_store_n */

#ifndef atomic_cas_n
#define atomic_cas_n(ptr, oval, nval, memorder)                     \
MACRO_BEGIN                                                         \
    typeof(*(ptr)) oval_;                                           \
                                                                    \
    oval_ = (oval);                                                 \
    __atomic_compare_exchange_n(ptr, &oval_, (nval), false,         \
                                memorder, __ATOMIC_RELAXED);        \
    oval_;                                                          \
MACRO_END
#endif /* atomic_cas_n */

#ifndef atomic_swap_n
#define atomic_swap_n __atomic_exchange_n
#endif /* atomic_swap_n */

#ifndef atomic_fetch_add_n
#define atomic_fetch_add_n __atomic_fetch_add
#endif /* atomic_fetch_add_n */

#ifndef atomic_fetch_sub_n
#define atomic_fetch_sub_n __atomic_fetch_sub
#endif /* atomic_fetch_sub_n */

#ifndef atomic_fetch_and_n
#define atomic_fetch_and_n __atomic_fetch_and
#endif /* atomic_fetch_and_n */

#ifndef atomic_fetch_or_n
#define atomic_fetch_or_n __atomic_fetch_or
#endif /* atomic_fetch_or_n */

#ifndef atomic_fetch_xor_n
#define atomic_fetch_xor_n __atomic_fetch_xor
#endif /* atomic_fetch_xor_n */

#ifndef atomic_add_n
#define atomic_add_n (void)__atomic_add_fetch
#endif /* atomic_add_n */

#ifndef atomic_sub_n
#define atomic_sub_n (void)__atomic_sub_fetch
#endif /* atomic_sub_n */

#ifndef atomic_and_n
#define atomic_and_n (void)__atomic_and_fetch
#endif /* atomic_and_n */

#ifndef atomic_or_n
#define atomic_or_n (void)__atomic_or_fetch
#endif /* atomic_or_n */

#ifndef atomic_xor_n
#define atomic_xor_n (void)__atomic_xor_fetch
#endif /* atomic_xor_n */

/*
 * This macro is used to select the appropriate function for the given
 * operation. The default expression is selected for pointer types.
 * In order to avoid confusing errors, all built-in types are explicitely
 * listed, so that unsupported ones don't select pointer operations.
 * Instead, they select a function with an explicit name indicating
 * an invalid type.
 */
#define atomic_select(ptr, op)                      \
_Generic(*(ptr),                                    \
                 float: atomic_invalid_type,        \
                double: atomic_invalid_type,        \
           long double: atomic_invalid_type,        \
                  bool: atomic_invalid_type,        \
                  char: atomic_invalid_type,        \
           signed char: atomic_invalid_type,        \
         unsigned char: atomic_invalid_type,        \
                 short: atomic_invalid_type,        \
        unsigned short: atomic_invalid_type,        \
                   int: atomic_ ## op ## _32,       \
          unsigned int: atomic_ ## op ## _32,       \
                  long: atomic_ ## op ## _ul,       \
         unsigned long: atomic_ ## op ## _ul,       \
             long long: atomic_ ## op ## _64,       \
    unsigned long long: atomic_ ## op ## _64,       \
               default: atomic_ ## op ## _ptr)

void atomic_invalid_type(void);

/*
 * After function selection, type genericity is achieved with transparent
 * unions, a GCC extension. Here are a few things to keep in mind :
 *  - all members must have the same representation
 *  - calling conventions are inferred from the first member
 */

#ifdef __LP64__

union atomic_ptr_32 {
    int *i_ptr;
    unsigned int *ui_ptr;
} __attribute__((transparent_union));

union atomic_constptr_32 {
    const int *i_ptr;
    const unsigned int *ui_ptr;
} __attribute__((transparent_union));

union atomic_val32 {
    int i;
    unsigned int ui;
} __attribute__((transparent_union));

#ifdef ATOMIC_HAVE_64B_OPS

union atomic_ptr_64 {
    void *ptr;
    unsigned long long *ull_ptr;
} __attribute__((transparent_union));

union atomic_constptr_64 {
    const void *ptr;
    const unsigned long long *ull_ptr;
} __attribute__((transparent_union));

union atomic_val_64 {
    void *ptr;
    long l;
    unsigned long ul;
    long long ll;
    unsigned long long ull;
} __attribute__((transparent_union));

#endif /* ATOMIC_HAVE_64B_OPS */

#else /* __LP64__ */

union atomic_ptr_32 {
    void *ptr;
    unsigned int *ui_ptr;
} __attribute__((transparent_union));

union atomic_constptr_32 {
    const void *ptr;
    const unsigned int *ui_ptr;
} __attribute__((transparent_union));

union atomic_val32 {
    void *ptr;
    int i;
    unsigned int ui;
    long l;
    unsigned long ul;
} __attribute__((transparent_union));

#ifdef ATOMIC_HAVE_64B_OPS

union atomic_ptr_64 {
    long long *ll_ptr;
    unsigned long long *ull_ptr;
} __attribute__((transparent_union));

union atomic_constptr_64 {
    const long long *ll_ptr;
    const unsigned long long *ull_ptr;
} __attribute__((transparent_union));

union atomic_val_64 {
    long long ll;
    unsigned long long ull;
} __attribute__((transparent_union));

#endif /* ATOMIC_HAVE_64B_OPS */

#endif /* __LP64__ */

#define atomic_ptr_aligned(ptr) P2ALIGNED((uintptr_t)(ptr), sizeof(ptr))

/* atomic_load */

static inline unsigned int
atomic_load_32(union atomic_constptr_32 ptr, int memorder)
{
    assert(atomic_ptr_aligned(ptr.ui_ptr));
    return atomic_load_n(ptr.ui_ptr, memorder);
}

#ifdef ATOMIC_HAVE_64B_OPS
static inline unsigned long long
atomic_load_64(union atomic_constptr_64 ptr, int memorder)
{
    assert(atomic_ptr_aligned(ptr.ull_ptr));
    return atomic_load_n(ptr.ull_ptr, memorder);
}
#else /* ATOMIC_HAVE_64B_OPS */
#define atomic_load_64 atomic_invalid_type
#endif /* ATOMIC_HAVE_64B_OPS */

#ifdef __LP64__
#define atomic_load_ul          atomic_load_64
#else /* __LP64__ */
#define atomic_load_ul          atomic_load_32
#endif /* __LP64__ */

#define atomic_load_ptr         atomic_load_ul

/* atomic_store */

static inline void
atomic_store_32(union atomic_ptr_32 ptr, union atomic_val32 val, int memorder)
{
    assert(atomic_ptr_aligned(ptr.ui_ptr));
    return atomic_store_n(ptr.ui_ptr, val.ui, memorder);
}

#ifdef ATOMIC_HAVE_64B_OPS
static inline void
atomic_store_64(union atomic_ptr_64 ptr, union atomic_val_64 val, int memorder)
{
    assert(atomic_ptr_aligned(ptr.ull_ptr));
    return atomic_store_n(ptr.ull_ptr, val.ull, memorder);
}
#else /* ATOMIC_HAVE_64B_OPS */
#define atomic_store_64 atomic_invalid_type
#endif /* ATOMIC_HAVE_64B_OPS */

#ifdef __LP64__
#define atomic_store_ul         atomic_store_64
#else /* __LP64__ */
#define atomic_store_ul         atomic_store_32
#endif /* __LP64__ */

#define atomic_store_ptr        atomic_store_ul

/* atomic_cas */

static inline unsigned int
atomic_cas_32(union atomic_ptr_32 ptr, union atomic_val32 oval,
              union atomic_val32 nval, int memorder)
{
    assert(atomic_ptr_aligned(ptr.ui_ptr));
    return atomic_cas_n(ptr.ui_ptr, oval.ui, nval.ui, memorder);
}

#ifdef ATOMIC_HAVE_64B_OPS
static inline unsigned long long
atomic_cas_64(union atomic_ptr_64 ptr, union atomic_val_64 oval,
              union atomic_val_64 nval, int memorder)
{
    assert(atomic_ptr_aligned(ptr.ull_ptr));
    return atomic_cas_n(ptr.ull_ptr, oval.ull, nval.ull, memorder);
}
#else /* ATOMIC_HAVE_64B_OPS */
#define atomic_cas_64 atomic_invalid_type
#endif /* ATOMIC_HAVE_64B_OPS */

#ifdef __LP64__
#define atomic_cas_ul           atomic_cas_64
#else /* __LP64__ */
#define atomic_cas_ul           atomic_cas_32
#endif /* __LP64__ */

#define atomic_cas_ptr          atomic_cas_ul

/* atomic_swap */

static inline unsigned int
atomic_swap_32(union atomic_ptr_32 ptr, union atomic_val32 val, int memorder)
{
    assert(atomic_ptr_aligned(ptr.ui_ptr));
    return atomic_swap_n(ptr.ui_ptr, val.ui, memorder);
}

#ifdef ATOMIC_HAVE_64B_OPS
static inline unsigned long long
atomic_swap_64(union atomic_ptr_64 ptr, union atomic_val_64 val, int memorder)
{
    assert(atomic_ptr_aligned(ptr.ull_ptr));
    return atomic_swap_n(ptr.ull_ptr, val.ull, memorder);
}
#else /* ATOMIC_HAVE_64B_OPS */
#define atomic_swap_64 atomic_invalid_type
#endif /* ATOMIC_HAVE_64B_OPS */

#ifdef __LP64__
#define atomic_swap_ul          atomic_swap_64
#else /* __LP64__ */
#define atomic_swap_ul          atomic_swap_32
#endif /* __LP64__ */

#define atomic_swap_ptr         atomic_swap_ul

/* atomic_fetch_add */

static inline unsigned int
atomic_fetch_add_32(union atomic_ptr_32 ptr, union atomic_val32 val,
                    int memorder)
{
    assert(atomic_ptr_aligned(ptr.ui_ptr));
    return atomic_fetch_add_n(ptr.ui_ptr, val.ui, memorder);
}

#ifdef ATOMIC_HAVE_64B_OPS
static inline unsigned long long
atomic_fetch_add_64(union atomic_ptr_64 ptr, union atomic_val_64 val,
                    int memorder)
{
    assert(atomic_ptr_aligned(ptr.ull_ptr));
    return atomic_fetch_add_n(ptr.ull_ptr, val.ull, memorder);
}
#else /* ATOMIC_HAVE_64B_OPS */
#define atomic_fetch_add_64 atomic_invalid_type
#endif /* ATOMIC_HAVE_64B_OPS */

#ifdef __LP64__
#define atomic_fetch_add_ul     atomic_fetch_add_64
#else /* __LP64__ */
#define atomic_fetch_add_ul     atomic_fetch_add_32
#endif /* __LP64__ */

#define atomic_fetch_add_ptr    atomic_fetch_add_ul

/* atomic_fetch_sub */

static inline unsigned int
atomic_fetch_sub_32(union atomic_ptr_32 ptr, union atomic_val32 val,
                    int memorder)
{
    assert(atomic_ptr_aligned(ptr.ui_ptr));
    return atomic_fetch_sub_n(ptr.ui_ptr, val.ui, memorder);
}

#ifdef ATOMIC_HAVE_64B_OPS
static inline unsigned long long
atomic_fetch_sub_64(union atomic_ptr_64 ptr, union atomic_val_64 val,
                    int memorder)
{
    assert(atomic_ptr_aligned(ptr.ull_ptr));
    return atomic_fetch_sub_n(ptr.ull_ptr, val.ull, memorder);
}
#else /* ATOMIC_HAVE_64B_OPS */
#define atomic_fetch_sub_64 atomic_invalid_type
#endif /* ATOMIC_HAVE_64B_OPS */

#ifdef __LP64__
#define atomic_fetch_sub_ul     atomic_fetch_sub_64
#else /* __LP64__ */
#define atomic_fetch_sub_ul     atomic_fetch_sub_32
#endif /* __LP64__ */

#define atomic_fetch_sub_ptr    atomic_fetch_sub_ul

/* atomic_fetch_and */

static inline unsigned int
atomic_fetch_and_32(union atomic_ptr_32 ptr, union atomic_val32 val,
                    int memorder)
{
    assert(atomic_ptr_aligned(ptr.ui_ptr));
    return atomic_fetch_and_n(ptr.ui_ptr, val.ui, memorder);
}

#ifdef ATOMIC_HAVE_64B_OPS
static inline unsigned long long
atomic_fetch_and_64(union atomic_ptr_64 ptr, union atomic_val_64 val,
                    int memorder)
{
    assert(atomic_ptr_aligned(ptr.ull_ptr));
    return atomic_fetch_and_n(ptr.ull_ptr, val.ull, memorder);
}
#else /* ATOMIC_HAVE_64B_OPS */
#define atomic_fetch_and_64 atomic_invalid_type
#endif /* ATOMIC_HAVE_64B_OPS */

#ifdef __LP64__
#define atomic_fetch_and_ul     atomic_fetch_and_64
#else /* __LP64__ */
#define atomic_fetch_and_ul     atomic_fetch_and_32
#endif /* __LP64__ */

#define atomic_fetch_and_ptr    atomic_fetch_and_ul

/* atomic_fetch_or */

static inline unsigned int
atomic_fetch_or_32(union atomic_ptr_32 ptr, union atomic_val32 val,
                   int memorder)
{
    assert(atomic_ptr_aligned(ptr.ui_ptr));
    return atomic_fetch_or_n(ptr.ui_ptr, val.ui, memorder);
}

#ifdef ATOMIC_HAVE_64B_OPS
static inline unsigned long long
atomic_fetch_or_64(union atomic_ptr_64 ptr, union atomic_val_64 val,
                   int memorder)
{
    assert(atomic_ptr_aligned(ptr.ull_ptr));
    return atomic_fetch_or_n(ptr.ull_ptr, val.ull, memorder);
}
#else /* ATOMIC_HAVE_64B_OPS */
#define atomic_or_64 atomic_invalid_type
#endif /* ATOMIC_HAVE_64B_OPS */

#ifdef __LP64__
#define atomic_fetch_or_ul      atomic_fetch_or_64
#else /* __LP64__ */
#define atomic_fetch_or_ul      atomic_fetch_or_32
#endif /* __LP64__ */

#define atomic_fetch_or_ptr     atomic_fetch_or_ul

/* atomic_fetch_xor */

static inline unsigned int
atomic_fetch_xor_32(union atomic_ptr_32 ptr, union atomic_val32 val,
                    int memorder)
{
    assert(atomic_ptr_aligned(ptr.ui_ptr));
    return atomic_fetch_xor_n(ptr.ui_ptr, val.ui, memorder);
}

#ifdef ATOMIC_HAVE_64B_OPS
static inline unsigned long long
atomic_fetch_xor_64(union atomic_ptr_64 ptr, union atomic_val_64 val,
                    int memorder)
{
    assert(atomic_ptr_aligned(ptr.ull_ptr));
    return atomic_fetch_xor_n(ptr.ull_ptr, val.ull, memorder);
}
#else /* ATOMIC_HAVE_64B_OPS */
#define atomic_xor_64 atomic_invalid_type
#endif /* ATOMIC_HAVE_64B_OPS */

#ifdef __LP64__
#define atomic_fetch_xor_ul     atomic_fetch_xor_64
#else /* __LP64__ */
#define atomic_fetch_xor_ul     atomic_fetch_xor_32
#endif /* __LP64__ */

#define atomic_fetch_xor_ptr    atomic_fetch_xor_ul

/* atomic_add */

static inline void
atomic_add_32(union atomic_ptr_32 ptr, union atomic_val32 val, int memorder)
{
    assert(atomic_ptr_aligned(ptr.ui_ptr));
    return atomic_add_n(ptr.ui_ptr, val.ui, memorder);
}

#ifdef ATOMIC_HAVE_64B_OPS
static inline void
atomic_add_64(union atomic_ptr_64 ptr, union atomic_val_64 val, int memorder)
{
    assert(atomic_ptr_aligned(ptr.ull_ptr));
    return atomic_add_n(ptr.ull_ptr, val.ull, memorder);
}
#else /* ATOMIC_HAVE_64B_OPS */
#define atomic_add_64 atomic_invalid_type
#endif /* ATOMIC_HAVE_64B_OPS */

#ifdef __LP64__
#define atomic_add_ul           atomic_add_64
#else /* __LP64__ */
#define atomic_add_ul           atomic_add_32
#endif /* __LP64__ */

#define atomic_add_ptr          atomic_add_ul

/* atomic_sub */

static inline void
atomic_sub_32(union atomic_ptr_32 ptr, union atomic_val32 val, int memorder)
{
    assert(atomic_ptr_aligned(ptr.ui_ptr));
    return atomic_sub_n(ptr.ui_ptr, val.ui, memorder);
}

#ifdef ATOMIC_HAVE_64B_OPS
static inline void
atomic_sub_64(union atomic_ptr_64 ptr, union atomic_val_64 val, int memorder)
{
    assert(atomic_ptr_aligned(ptr.ull_ptr));
    return atomic_sub_n(ptr.ull_ptr, val.ull, memorder);
}
#else /* ATOMIC_HAVE_64B_OPS */
#define atomic_sub_64 atomic_invalid_type
#endif /* ATOMIC_HAVE_64B_OPS */

#ifdef __LP64__
#define atomic_sub_ul           atomic_sub_64
#else /* __LP64__ */
#define atomic_sub_ul           atomic_sub_32
#endif /* __LP64__ */

#define atomic_sub_ptr          atomic_sub_ul

/* atomic_and */

static inline void
atomic_and_32(union atomic_ptr_32 ptr, union atomic_val32 val, int memorder)
{
    assert(atomic_ptr_aligned(ptr.ui_ptr));
    return atomic_and_n(ptr.ui_ptr, val.ui, memorder);
}

#ifdef ATOMIC_HAVE_64B_OPS
static inline void
atomic_and_64(union atomic_ptr_64 ptr, union atomic_val_64 val, int memorder)
{
    assert(atomic_ptr_aligned(ptr.ull_ptr));
    return atomic_and_n(ptr.ull_ptr, val.ull, memorder);
}
#else /* ATOMIC_HAVE_64B_OPS */
#define atomic_and_64 atomic_invalid_type
#endif /* ATOMIC_HAVE_64B_OPS */

#ifdef __LP64__
#define atomic_and_ul           atomic_and_64
#else /* __LP64__ */
#define atomic_and_ul           atomic_and_32
#endif /* __LP64__ */

#define atomic_and_ptr          atomic_and_ul

/* atomic_or */

static inline void
atomic_or_32(union atomic_ptr_32 ptr, union atomic_val32 val, int memorder)
{
    assert(atomic_ptr_aligned(ptr.ui_ptr));
    return atomic_or_n(ptr.ui_ptr, val.ui, memorder);
}

#ifdef ATOMIC_HAVE_64B_OPS
static inline void
atomic_or_64(union atomic_ptr_64 ptr, union atomic_val_64 val, int memorder)
{
    assert(atomic_ptr_aligned(ptr.ull_ptr));
    return atomic_or_n(ptr.ull_ptr, val.ull, memorder);
}
#else /* ATOMIC_HAVE_64B_OPS */
#define atomic_or_64 atomic_invalid_type
#endif /* ATOMIC_HAVE_64B_OPS */

#ifdef __LP64__
#define atomic_or_ul            atomic_or_64
#else /* __LP64__ */
#define atomic_or_ul            atomic_or_32
#endif /* __LP64__ */

#define atomic_or_ptr           atomic_or_ul

/* atomic_xor */

static inline void
atomic_xor_32(union atomic_ptr_32 ptr, union atomic_val32 val, int memorder)
{
    assert(atomic_ptr_aligned(ptr.ui_ptr));
    return atomic_xor_n(ptr.ui_ptr, val.ui, memorder);
}

#ifdef ATOMIC_HAVE_64B_OPS
static inline void
atomic_xor_64(union atomic_ptr_64 ptr, union atomic_val_64 val, int memorder)
{
    assert(atomic_ptr_aligned(ptr.ull_ptr));
    return atomic_xor_n(ptr.ull_ptr, val.ull, memorder);
}
#else /* ATOMIC_HAVE_64B_OPS */
#define atomic_xor_64 atomic_invalid_type
#endif /* ATOMIC_HAVE_64B_OPS */

#ifdef __LP64__
#define atomic_xor_ul           atomic_xor_64
#else /* __LP64__ */
#define atomic_xor_ul           atomic_xor_32
#endif /* __LP64__ */

#define atomic_xor_ptr          atomic_xor_ul

#endif /* KERN_ATOMIC_I_H */
