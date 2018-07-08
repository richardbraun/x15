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
 * Architecture-specific code may override any of the type-specific
 * functions by defining a macro of the same name.
 */

#ifndef KERN_LATOMIC_I_H
#define KERN_LATOMIC_I_H

#include <stdbool.h>
#include <stdint.h>

#include <kern/atomic_types.h>
#include <kern/macros.h>
#include <machine/latomic.h>

#define LATOMIC_ALIGN(ptr) MIN(sizeof(*(ptr)), sizeof(ptr))
#define latomic_ptr_aligned(ptr) P2ALIGNED((uintptr_t)(ptr), LATOMIC_ALIGN(ptr))

/* See atomic_select */
#define latomic_select(ptr, op)                     \
_Generic(*(ptr),                                    \
                 float: latomic_invalid_type,       \
                double: latomic_invalid_type,       \
           long double: latomic_invalid_type,       \
                  bool: latomic_invalid_type,       \
                  char: latomic_invalid_type,       \
           signed char: latomic_invalid_type,       \
         unsigned char: latomic_invalid_type,       \
                 short: latomic_invalid_type,       \
        unsigned short: latomic_invalid_type,       \
                   int: latomic_ ## op ## _32,      \
          unsigned int: latomic_ ## op ## _32,      \
                  long: latomic_ ## op ## _ul,      \
         unsigned long: latomic_ ## op ## _ul,      \
             long long: latomic_ ## op ## _64,      \
    unsigned long long: latomic_ ## op ## _64,      \
               default: latomic_ ## op ## _ptr)

void latomic_invalid_type(void);

/* latomic_load */

#ifndef latomic_load_32
unsigned int latomic_load_32(union atomic_constptr_32 ptr, int memorder);
#endif /* latomic_load_32 */

#ifndef latomic_load_64
#ifdef __LP64__
unsigned long long latomic_load_64(union atomic_constptr_64 ptr, int memorder);
#else /* __LP64__ */
unsigned long long latomic_load_64(union atomic_constptr_64 ptr, int memorder);
#endif /* __LP64__ */
#endif /* latomic_load_64 */

#ifdef __LP64__
#define latomic_load_ul          latomic_load_64
#else /* __LP64__ */
#define latomic_load_ul          latomic_load_32
#endif /* __LP64__ */

#define latomic_load_ptr         latomic_load_ul


/* latomic_store */

#ifndef latomic_store_32
void latomic_store_32(union atomic_ptr_32 ptr, union atomic_val_32 val,
                      int memorder);
#endif /* latomic_store_32 */

#ifndef latomic_store_64
#ifdef __LP64__
void latomic_store_64(union atomic_ptr_64 ptr, union atomic_val_64 val,
                      int memorder);
#else /* __LP64__ */
void latomic_store_64(union atomic_ptr_64 ptr, union atomic_val_64 val,
                      int memorder);
#endif /* __LP64__ */
#endif /* latomic_store_64 */

#ifdef __LP64__
#define latomic_store_ul        latomic_store_64
#else /* __LP64__ */
#define latomic_store_ul        latomic_store_32
#endif /* __LP64__ */

#define latomic_store_ptr       latomic_store_ul


/* latomic_swap */

#ifndef latomic_swap_32
unsigned int latomic_swap_32(union atomic_ptr_32 ptr,
                             union atomic_val_32 val, int memorder);
#endif /* latomic_swap_32 */

#ifndef latomic_swap_64
unsigned long long latomic_swap_64(union atomic_ptr_64 ptr,
                                   union atomic_val_64 val, int memorder);
#endif /* latomic_swap_64 */

#ifdef __LP64__
#define latomic_swap_ul         latomic_swap_64
#else /* __LP64__ */
#define latomic_swap_ul         latomic_swap_32
#endif /* __LP64__ */

#define latomic_swap_ptr        latomic_swap_ul


/* latomic_cas */

#ifndef latomic_cas_32
unsigned int latomic_cas_32(union atomic_ptr_32 ptr, union atomic_val_32 oval,
                            union atomic_val_32 nval, int memorder);
#endif /* latomic_cas_32 */

#ifndef latomic_cas_64
unsigned long long latomic_cas_64(union atomic_ptr_64 ptr,
                                  union atomic_val_64 oval,
                                  union atomic_val_64 nval, int memorder);
#endif /* latomic_cas_64 */

#ifdef __LP64__
#define latomic_cas_ul          latomic_cas_64
#else /* __LP64__ */
#define latomic_cas_ul          latomic_cas_32
#endif /* __LP64__ */

#define latomic_cas_ptr         latomic_cas_ul


/* latomic_fetch_add */

#ifndef latomic_fetch_add_32
unsigned int latomic_fetch_add_32(union atomic_ptr_32 ptr,
                                  union atomic_val_32 val, int memorder);
#endif /* latomic_fetch_add_32 */

#ifndef latomic_fetch_add_64
unsigned long long latomic_fetch_add_64(union atomic_ptr_64 ptr,
                                        union atomic_val_64 val, int memorder);
#endif /* latomic_fetch_add_64 */

#ifdef __LP64__
#define latomic_fetch_add_ul    latomic_fetch_add_64
#else /* __LP64__ */
#define latomic_fetch_add_ul    latomic_fetch_add_32
#endif /* __LP64__ */

#define latomic_fetch_add_ptr   latomic_fetch_add_ul


/* latomic_fetch_sub */

#ifndef latomic_fetch_sub_32
unsigned int latomic_fetch_sub_32(union atomic_ptr_32 ptr,
                                  union atomic_val_32 val, int memorder);
#endif /* latomic_fetch_sub_32 */

#ifndef latomic_fetch_sub_64
unsigned long long latomic_fetch_sub_64(union atomic_ptr_64 ptr,
                                        union atomic_val_64 val, int memorder);
#endif /* latomic_fetch_sub_64 */

#ifdef __LP64__
#define latomic_fetch_sub_ul    latomic_fetch_sub_64
#else /* __LP64__ */
#define latomic_fetch_sub_ul    latomic_fetch_sub_32
#endif /* __LP64__ */

#define latomic_fetch_sub_ptr   latomic_fetch_sub_ul


/* latomic_fetch_and */

#ifndef latomic_fetch_and_32
unsigned int latomic_fetch_and_32(union atomic_ptr_32 ptr,
                                  union atomic_val_32 val, int memorder);
#endif /* latomic_fetch_and_32 */

#ifndef latomic_fetch_and_64
unsigned long long latomic_fetch_and_64(union atomic_ptr_64 ptr,
                                        union atomic_val_64 val, int memorder);
#endif /* latomic_fetch_and_64 */

#ifdef __LP64__
#define latomic_fetch_and_ul    latomic_fetch_and_64
#else /* __LP64__ */
#define latomic_fetch_and_ul    latomic_fetch_and_32
#endif /* __LP64__ */

#define latomic_fetch_and_ptr   latomic_fetch_and_ul


/* latomic_fetch_or */

#ifndef latomic_fetch_or_32
unsigned int latomic_fetch_or_32(union atomic_ptr_32 ptr,
                                 union atomic_val_32 val, int memorder);
#endif /* latomic_fetch_or_32 */

#ifndef latomic_fetch_or_64
unsigned long long latomic_fetch_or_64(union atomic_ptr_64 ptr,
                                       union atomic_val_64 val, int memorder);
#endif /* latomic_fetch_or_64 */

#ifdef __LP64__
#define latomic_fetch_or_ul     latomic_fetch_or_64
#else /* __LP64__ */
#define latomic_fetch_or_ul     latomic_fetch_or_32
#endif /* __LP64__ */

#define latomic_fetch_or_ptr    latomic_fetch_or_ul


/* latomic_fetch_xor */

#ifndef latomic_fetch_xor_32
unsigned int latomic_fetch_xor_32(union atomic_ptr_32 ptr,
                                  union atomic_val_32 val, int memorder);
#endif /* latomic_fetch_xor_32 */

#ifndef latomic_fetch_xor_64
unsigned long long latomic_fetch_xor_64(union atomic_ptr_64 ptr,
                                        union atomic_val_64 val, int memorder);
#endif /* latomic_fetch_xor_64 */

#ifdef __LP64__
#define latomic_fetch_xor_ul    latomic_fetch_xor_64
#else /* __LP64__ */
#define latomic_fetch_xor_ul    latomic_fetch_xor_32
#endif /* __LP64__ */

#define latomic_fetch_xor_ptr   latomic_fetch_xor_ul


/* latomic_add */

#ifndef latomic_add_32
void latomic_add_32(union atomic_ptr_32 ptr, union atomic_val_32 val,
                    int memorder);
#endif /* latomic_add_32 */

#ifndef latomic_add_64
void latomic_add_64(union atomic_ptr_64 ptr, union atomic_val_64 val,
                    int memorder);
#endif /* latomic_add_64 */

#ifdef __LP64__
#define latomic_add_ul          latomic_add_64
#else /* __LP64__ */
#define latomic_add_ul          latomic_add_32
#endif /* __LP64__ */

#define latomic_add_ptr         latomic_add_ul


/* latomic_sub */

#ifndef latomic_sub_32
void latomic_sub_32(union atomic_ptr_32 ptr, union atomic_val_32 val,
                    int memorder);
#endif /* latomic_sub_32 */

#ifndef latomic_sub_64
void latomic_sub_64(union atomic_ptr_64 ptr, union atomic_val_64 val,
                    int memorder);
#endif /* latomic_sub_64 */

#ifdef __LP64__
#define latomic_sub_ul          latomic_sub_64
#else /* __LP64__ */
#define latomic_sub_ul          latomic_sub_32
#endif /* __LP64__ */

#define latomic_sub_ptr         latomic_sub_ul


/* latomic_and */

#ifndef latomic_and_32
void latomic_and_32(union atomic_ptr_32 ptr, union atomic_val_32 val,
                    int memorder);
#endif /* latomic_and_32 */

#ifndef latomic_and_64
void latomic_and_64(union atomic_ptr_64 ptr, union atomic_val_64 val,
                    int memorder);
#endif /* latomic_and_64 */

#ifdef __LP64__
#define latomic_and_ul          latomic_and_64
#else /* __LP64__ */
#define latomic_and_ul          latomic_and_32
#endif /* __LP64__ */

#define latomic_and_ptr         latomic_and_ul


/* latomic_or */

#ifndef latomic_or_32
void latomic_or_32(union atomic_ptr_32 ptr, union atomic_val_32 val,
                   int memorder);
#endif /* latomic_or_32 */

#ifndef latomic_or_64
void latomic_or_64(union atomic_ptr_64 ptr, union atomic_val_64 val,
                   int memorder);
#endif /* latomic_or_64 */

#ifdef __LP64__
#define latomic_or_ul           latomic_or_64
#else /* __LP64__ */
#define latomic_or_ul           latomic_or_32
#endif /* __LP64__ */

#define latomic_or_ptr          latomic_or_ul


/* latomic_xor */

#ifndef latomic_xor_32
void latomic_xor_32(union atomic_ptr_32 ptr, union atomic_val_32 val,
                    int memorder);
#endif /* latomic_xor_32 */

#ifndef latomic_xor_64
void latomic_xor_64(union atomic_ptr_64 ptr, union atomic_val_64 val,
                    int memorder);
#endif /* latomic_xor_64 */

#ifdef __LP64__
#define latomic_xor_ul          latomic_xor_64
#else /* __LP64__ */
#define latomic_xor_ul          latomic_xor_32
#endif /* __LP64__ */

#define latomic_xor_ptr         latomic_xor_ul

#endif /* KERN_LATOMIC_I_H */
