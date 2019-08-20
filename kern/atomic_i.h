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
 * Architecture-specific code may override any of the type-specific
 * functions by defining a macro of the same name.
 */

#ifndef KERN_ATOMIC_I_H
#define KERN_ATOMIC_I_H

#include <stdbool.h>
#include <stdint.h>

#include <kern/atomic_types.h>
#include <kern/macros.h>
#include <machine/atomic.h>

#define ATOMIC_ALIGN(ptr) MIN(sizeof(*(ptr)), sizeof(ptr))
#define atomic_ptr_aligned(ptr) P2ALIGNED((uintptr_t)(ptr), ATOMIC_ALIGN(ptr))

/*
 * This macro is used to select the appropriate function for the given
 * operation. The default expression is selected for pointer types.
 * In order to avoid confusing errors, all built-in types are explicitely
 * listed, so that unsupported ones don't select pointer operations.
 * Instead, they select a function with an explicit name indicating
 * an invalid type.
 *
 * TODO Fix implementation for signed types.
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


/* atomic_load */

#ifndef atomic_load_32
static inline unsigned int
atomic_load_32(union atomic_constptr_32 ptr, int memorder)
{
    return __atomic_load_n(ptr.ui_ptr, memorder);
}
#endif /* atomic_load_32 */

#ifdef ATOMIC_HAVE_64B_OPS
#ifndef atomic_load_64
static inline unsigned long long
atomic_load_64(union atomic_constptr_64 ptr, int memorder)
{
    return __atomic_load_n(ptr.ull_ptr, memorder);
}
#endif /* atomic_load_64 */

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

#ifndef atomic_store_32
static inline void
atomic_store_32(union atomic_ptr_32 ptr, union atomic_val_32 val, int memorder)
{
    return __atomic_store_n(ptr.ui_ptr, val.ui, memorder);
}
#endif /* atomic_store_32 */

#ifdef ATOMIC_HAVE_64B_OPS
#ifndef atomic_store_64
static inline void
atomic_store_64(union atomic_ptr_64 ptr, union atomic_val_64 val, int memorder)
{
    return __atomic_store_n(ptr.ull_ptr, val.ull, memorder);
}
#endif /* atomic_store_64 */

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

#define atomic_cas_n(ptr, oval, nval, memorder)                     \
MACRO_BEGIN                                                         \
    typeof(oval) oval_;                                             \
                                                                    \
    oval_ = (oval);                                                 \
    __atomic_compare_exchange_n(ptr, &oval_, (nval), false,         \
                                memorder, __ATOMIC_RELAXED);        \
    oval_;                                                          \
MACRO_END

#ifndef atomic_cas_32
static inline unsigned int
atomic_cas_32(union atomic_ptr_32 ptr, union atomic_val_32 oval,
              union atomic_val_32 nval, int memorder)
{
    return atomic_cas_n(ptr.ui_ptr, oval.ui, nval.ui, memorder);
}
#endif /* atomic_cas_32 */

#ifdef ATOMIC_HAVE_64B_OPS
#ifndef atomic_cas_64
static inline unsigned long long
atomic_cas_64(union atomic_ptr_64 ptr, union atomic_val_64 oval,
              union atomic_val_64 nval, int memorder)
{
    return atomic_cas_n(ptr.ull_ptr, oval.ull, nval.ull, memorder);
}
#endif /* atomic_cas_64 */

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

#ifndef atomic_swap_32
static inline unsigned int
atomic_swap_32(union atomic_ptr_32 ptr, union atomic_val_32 val, int memorder)
{
    return __atomic_exchange_n(ptr.ui_ptr, val.ui, memorder);
}
#endif /* atomic_swap_32 */

#ifdef ATOMIC_HAVE_64B_OPS
#ifndef atomic_swap_64
static inline unsigned long long
atomic_swap_64(union atomic_ptr_64 ptr, union atomic_val_64 val, int memorder)
{
    return __atomic_exchange_n(ptr.ull_ptr, val.ull, memorder);
}
#endif /* atomic_swap_64 */

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

#ifndef atomic_fetch_add_32
static inline unsigned int
atomic_fetch_add_32(union atomic_ptr_32 ptr, union atomic_val_32 val,
                    int memorder)
{
    return __atomic_fetch_add(ptr.ui_ptr, val.ui, memorder);
}
#endif /* atomic_fetch_add_32 */

#ifdef ATOMIC_HAVE_64B_OPS
#ifndef atomic_fetch_add_64
static inline unsigned long long
atomic_fetch_add_64(union atomic_ptr_64 ptr, union atomic_val_64 val,
                    int memorder)
{
    return __atomic_fetch_add(ptr.ull_ptr, val.ull, memorder);
}
#endif /* atomic_fetch_add_64 */

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

#ifndef atomic_fetch_sub_32
static inline unsigned int
atomic_fetch_sub_32(union atomic_ptr_32 ptr, union atomic_val_32 val,
                    int memorder)
{
    return __atomic_fetch_sub(ptr.ui_ptr, val.ui, memorder);
}
#endif /* atomic_fetch_sub_32 */

#ifdef ATOMIC_HAVE_64B_OPS
#ifndef atomic_fetch_sub_64
static inline unsigned long long
atomic_fetch_sub_64(union atomic_ptr_64 ptr, union atomic_val_64 val,
                    int memorder)
{
    return __atomic_fetch_sub(ptr.ull_ptr, val.ull, memorder);
}
#endif /* atomic_fetch_sub_64 */

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

#ifndef atomic_fetch_and_32
static inline unsigned int
atomic_fetch_and_32(union atomic_ptr_32 ptr, union atomic_val_32 val,
                    int memorder)
{
    return __atomic_fetch_and(ptr.ui_ptr, val.ui, memorder);
}
#endif /* atomic_fetch_and_32 */

#ifdef ATOMIC_HAVE_64B_OPS
#ifndef atomic_fetch_and_64
static inline unsigned long long
atomic_fetch_and_64(union atomic_ptr_64 ptr, union atomic_val_64 val,
                    int memorder)
{
    return __atomic_fetch_and(ptr.ull_ptr, val.ull, memorder);
}
#endif /* atomic_fetch_and_64 */

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

#ifndef atomic_fetch_or_32
static inline unsigned int
atomic_fetch_or_32(union atomic_ptr_32 ptr, union atomic_val_32 val,
                   int memorder)
{
    return __atomic_fetch_or(ptr.ui_ptr, val.ui, memorder);
}
#endif /* atomic_fetch_or_32 */

#ifdef ATOMIC_HAVE_64B_OPS
#ifndef atomic_fetch_or_64
static inline unsigned long long
atomic_fetch_or_64(union atomic_ptr_64 ptr, union atomic_val_64 val,
                   int memorder)
{
    return __atomic_fetch_or(ptr.ull_ptr, val.ull, memorder);
}
#endif /* atomic_fetch_or_64 */

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

#ifndef atomic_fetch_xor_32
static inline unsigned int
atomic_fetch_xor_32(union atomic_ptr_32 ptr, union atomic_val_32 val,
                    int memorder)
{
    return __atomic_fetch_xor(ptr.ui_ptr, val.ui, memorder);
}
#endif /* atomic_fetch_xor_32 */

#ifdef ATOMIC_HAVE_64B_OPS
#ifndef atomic_fetch_xor_64
static inline unsigned long long
atomic_fetch_xor_64(union atomic_ptr_64 ptr, union atomic_val_64 val,
                    int memorder)
{
    return __atomic_fetch_xor(ptr.ull_ptr, val.ull, memorder);
}
#endif /* atomic_fetch_xor_64 */

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

#ifndef atomic_add_32
static inline void
atomic_add_32(union atomic_ptr_32 ptr, union atomic_val_32 val, int memorder)
{
    __atomic_add_fetch(ptr.ui_ptr, val.ui, memorder);
}
#endif /* atomic_add_32 */

#ifdef ATOMIC_HAVE_64B_OPS
#ifndef atomic_add_64
static inline void
atomic_add_64(union atomic_ptr_64 ptr, union atomic_val_64 val, int memorder)
{
    __atomic_add_fetch(ptr.ull_ptr, val.ull, memorder);
}
#endif /* atomic_add_64 */

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

#ifndef atomic_sub_32
static inline void
atomic_sub_32(union atomic_ptr_32 ptr, union atomic_val_32 val, int memorder)
{
    __atomic_sub_fetch(ptr.ui_ptr, val.ui, memorder);
}
#endif /* atomic_sub_32 */

#ifdef ATOMIC_HAVE_64B_OPS
#ifndef atomic_sub_64
static inline void
atomic_sub_64(union atomic_ptr_64 ptr, union atomic_val_64 val, int memorder)
{
    __atomic_sub_fetch(ptr.ull_ptr, val.ull, memorder);
}
#endif /* atomic_sub_64 */

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

#ifndef atomic_and_32
static inline void
atomic_and_32(union atomic_ptr_32 ptr, union atomic_val_32 val, int memorder)
{
    __atomic_and_fetch(ptr.ui_ptr, val.ui, memorder);
}
#endif /* atomic_and_32 */

#ifdef ATOMIC_HAVE_64B_OPS
#ifndef atomic_and_64
static inline void
atomic_and_64(union atomic_ptr_64 ptr, union atomic_val_64 val, int memorder)
{
    __atomic_and_fetch(ptr.ull_ptr, val.ull, memorder);
}
#endif /* atomic_and_64 */

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

#ifndef atomic_or_32
static inline void
atomic_or_32(union atomic_ptr_32 ptr, union atomic_val_32 val, int memorder)
{
    __atomic_or_fetch(ptr.ui_ptr, val.ui, memorder);
}
#endif /* atomic_or_32 */

#ifdef ATOMIC_HAVE_64B_OPS
#ifndef atomic_or_64
static inline void
atomic_or_64(union atomic_ptr_64 ptr, union atomic_val_64 val, int memorder)
{
    __atomic_or_fetch(ptr.ull_ptr, val.ull, memorder);
}
#endif /* atomic_or_64 */

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

#ifndef atomic_xor_32
static inline void
atomic_xor_32(union atomic_ptr_32 ptr, union atomic_val_32 val, int memorder)
{
    __atomic_xor_fetch(ptr.ui_ptr, val.ui, memorder);
}
#endif /* atomic_xor_32 */

#ifdef ATOMIC_HAVE_64B_OPS
#ifndef atomic_xor_64
static inline void
atomic_xor_64(union atomic_ptr_64 ptr, union atomic_val_64 val, int memorder)
{
    __atomic_xor_fetch(ptr.ull_ptr, val.ull, memorder);
}
#endif /* atomic_xor_64 */

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
