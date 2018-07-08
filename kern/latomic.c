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

#include <kern/atomic_types.h>
#include <kern/latomic.h>
#include <kern/latomic_i.h>
#include <kern/macros.h>
#include <machine/cpu.h>
#include <machine/latomic.h>

#define latomic_swap_n(ptr, val)                    \
MACRO_BEGIN                                         \
    unsigned long flags_;                           \
    typeof(val) ret_;                               \
                                                    \
    cpu_intr_save(&flags_);                         \
    ret_ = *(ptr);                                  \
    *(ptr) = (val);                                 \
    cpu_intr_restore(flags_);                       \
                                                    \
    ret_;                                           \
MACRO_END

#define latomic_cas_n(ptr, oval, nval)              \
MACRO_BEGIN                                         \
    unsigned long flags_;                           \
    typeof(oval) ret_;                              \
                                                    \
    cpu_intr_save(&flags_);                         \
                                                    \
    ret_ = *(ptr);                                  \
                                                    \
    if (ret_ == (oval)) {                           \
        *(ptr) = (nval);                            \
    }                                               \
                                                    \
    cpu_intr_restore(flags_);                       \
                                                    \
    ret_;                                           \
MACRO_END

#define latomic_fetch_op_n(ptr, val, op)            \
MACRO_BEGIN                                         \
    unsigned long flags_;                           \
    typeof(val) ret_;                               \
                                                    \
    cpu_intr_save(&flags_);                         \
    ret_ = *(ptr);                                  \
    *(ptr) = ret_ op (val);                         \
    cpu_intr_restore(flags_);                       \
                                                    \
    ret_;                                           \
MACRO_END

#define latomic_fetch_add_n(ptr, val)   latomic_fetch_op_n(ptr, val, +)
#define latomic_fetch_sub_n(ptr, val)   latomic_fetch_op_n(ptr, val, -)
#define latomic_fetch_and_n(ptr, val)   latomic_fetch_op_n(ptr, val, &)
#define latomic_fetch_or_n(ptr, val)    latomic_fetch_op_n(ptr, val, |)
#define latomic_fetch_xor_n(ptr, val)   latomic_fetch_op_n(ptr, val, ^)


/* latomic_load */

#ifndef latomic_load_32
unsigned int
latomic_load_32(union atomic_constptr_32 ptr, int memorder)
{
    return __atomic_load_n(ptr.ui_ptr, memorder);
}
#endif /* latomic_load_32 */

#ifndef latomic_load_64
#ifdef __LP64__
unsigned long long
latomic_load_64(union atomic_constptr_64 ptr, int memorder)
{
    return __atomic_load_n(ptr.ull_ptr, memorder);
}
#else /* __LP64__ */
unsigned long long
latomic_load_64(union atomic_constptr_64 ptr, int memorder)
{
    unsigned long long ret;
    unsigned long flags;

    (void)memorder;

    cpu_intr_save(&flags);
    ret = *ptr.ull_ptr;
    cpu_intr_restore(flags);

    return ret;
}
#endif /* __LP64__ */
#endif /* latomic_load_64 */

/* latomic_store */

#ifndef latomic_store_32
void
latomic_store_32(union atomic_ptr_32 ptr, union atomic_val_32 val, int memorder)
{
    __atomic_store_n(ptr.ui_ptr, val.ui, memorder);
}
#endif /* latomic_store_32 */

#ifndef latomic_store_64
#ifdef __LP64__
void
latomic_store_64(union atomic_ptr_64 ptr, union atomic_val_64 val, int memorder)
{
    return __atomic_store_n(ptr.ull_ptr, val.ull, memorder);
}
#else /* __LP64__ */
void
latomic_store_64(union atomic_ptr_64 ptr, union atomic_val_64 val, int memorder)
{
    unsigned long flags;

    (void)memorder;

    cpu_intr_save(&flags);
    *ptr.ull_ptr = val.ull;
    cpu_intr_restore(flags);
}
#endif /* __LP64__ */
#endif /* latomic_store_64 */

/* latomic_swap */

#ifndef latomic_swap_32
unsigned int
latomic_swap_32(union atomic_ptr_32 ptr, union atomic_val_32 val, int memorder)
{
    (void)memorder;
    return latomic_swap_n(ptr.ui_ptr, val.ui);
}
#endif /* latomic_swap_32 */

#ifndef latomic_swap_64
unsigned long long
latomic_swap_64(union atomic_ptr_64 ptr, union atomic_val_64 val, int memorder)
{
    (void)memorder;
    return latomic_swap_n(ptr.ull_ptr, val.ull);
}
#endif /* latomic_swap_64 */

/* latomic_cas */

#ifndef latomic_cas_32
unsigned int
latomic_cas_32(union atomic_ptr_32 ptr, union atomic_val_32 oval,
               union atomic_val_32 nval, int memorder)
{
    (void)memorder;
    return latomic_cas_n(ptr.ui_ptr, oval.ui, nval.ui);
}
#endif /* latomic_cas_32 */

#ifndef latomic_cas_64
unsigned long long
latomic_cas_64(union atomic_ptr_64 ptr, union atomic_val_64 oval,
               union atomic_val_64 nval, int memorder)
{
    (void)memorder;
    return latomic_cas_n(ptr.ull_ptr, oval.ull, nval.ull);
}
#endif /* latomic_cas_64 */

/* latomic_fetch_add */

#ifndef latomic_fetch_add_32
unsigned int
latomic_fetch_add_32(union atomic_ptr_32 ptr, union atomic_val_32 val,
                     int memorder)
{
    (void)memorder;
    return latomic_fetch_add_n(ptr.ui_ptr, val.ui);
}
#endif /* latomic_fetch_add_32 */

#ifndef latomic_fetch_add_64
unsigned long long
latomic_fetch_add_64(union atomic_ptr_64 ptr, union atomic_val_64 val,
                     int memorder)
{
    (void)memorder;
    return latomic_fetch_add_n(ptr.ull_ptr, val.ull);
}
#endif /* latomic_fetch_add_64 */

/* latomic_fetch_sub */

#ifndef latomic_fetch_sub_32
unsigned int
latomic_fetch_sub_32(union atomic_ptr_32 ptr, union atomic_val_32 val,
                     int memorder)
{
    (void)memorder;
    return latomic_fetch_sub_n(ptr.ui_ptr, val.ui);
}
#endif /* latomic_fetch_sub_32 */

#ifndef latomic_fetch_sub_64
unsigned long long
latomic_fetch_sub_64(union atomic_ptr_64 ptr, union atomic_val_64 val,
                     int memorder)
{
    (void)memorder;
    return latomic_fetch_sub_n(ptr.ull_ptr, val.ull);
}
#endif /* latomic_fetch_sub_64 */

/* latomic_fetch_and */

#ifndef latomic_fetch_and_32
unsigned int
latomic_fetch_and_32(union atomic_ptr_32 ptr, union atomic_val_32 val,
                     int memorder)
{
    (void)memorder;
    return latomic_fetch_and_n(ptr.ui_ptr, val.ui);
}
#endif /* latomic_fetch_and_32 */

#ifndef latomic_fetch_and_64
unsigned long long
latomic_fetch_and_64(union atomic_ptr_64 ptr, union atomic_val_64 val,
                     int memorder)
{
    (void)memorder;
    return latomic_fetch_and_n(ptr.ull_ptr, val.ull);
}
#endif /* latomic_fetch_and_64 */

/* latomic_fetch_or */

#ifndef latomic_fetch_or_32
unsigned int
latomic_fetch_or_32(union atomic_ptr_32 ptr, union atomic_val_32 val,
                    int memorder)
{
    (void)memorder;
    return latomic_fetch_or_n(ptr.ui_ptr, val.ui);
}
#endif /* latomic_fetch_or_32 */

#ifndef latomic_fetch_or_64
unsigned long long
latomic_fetch_or_64(union atomic_ptr_64 ptr, union atomic_val_64 val,
                    int memorder)
{
    (void)memorder;
    return latomic_fetch_or_n(ptr.ull_ptr, val.ull);
}
#endif /* latomic_fetch_or_64 */

/* latomic_fetch_xor */

#ifndef latomic_fetch_xor_32
unsigned int
latomic_fetch_xor_32(union atomic_ptr_32 ptr, union atomic_val_32 val,
                     int memorder)
{
    (void)memorder;
    return latomic_fetch_xor_n(ptr.ui_ptr, val.ui);
}
#endif /* latomic_fetch_xor_32 */

#ifndef latomic_fetch_xor_64
unsigned long long
latomic_fetch_xor_64(union atomic_ptr_64 ptr, union atomic_val_64 val,
                     int memorder)
{
    (void)memorder;
    return latomic_fetch_xor_n(ptr.ull_ptr, val.ull);
}
#endif /* latomic_fetch_xor_64 */

/* latomic_add */

#ifndef latomic_add_32
void
latomic_add_32(union atomic_ptr_32 ptr, union atomic_val_32 val, int memorder)
{
    (void)memorder;
    latomic_fetch_add_n(ptr.ui_ptr, val.ui);
}
#endif /* latomic_add_32 */

#ifndef latomic_add_64
void
latomic_add_64(union atomic_ptr_64 ptr, union atomic_val_64 val, int memorder)
{
    (void)memorder;
    latomic_fetch_add_n(ptr.ull_ptr, val.ull);
}
#endif /* latomic_add_64 */

/* latomic_sub */

#ifndef latomic_sub_32
void
latomic_sub_32(union atomic_ptr_32 ptr, union atomic_val_32 val, int memorder)
{
    (void)memorder;
    latomic_fetch_sub_n(ptr.ui_ptr, val.ui);
}
#endif /* latomic_sub_32 */

#ifndef latomic_sub_64
void
latomic_sub_64(union atomic_ptr_64 ptr, union atomic_val_64 val, int memorder)
{
    (void)memorder;
    latomic_fetch_sub_n(ptr.ull_ptr, val.ull);
}
#endif /* latomic_sub_64 */

/* latomic_and */

#ifndef latomic_and_32
void
latomic_and_32(union atomic_ptr_32 ptr, union atomic_val_32 val, int memorder)
{
    (void)memorder;
    latomic_fetch_and_n(ptr.ui_ptr, val.ui);
}
#endif /* latomic_and_32 */

#ifndef latomic_and_64
void
latomic_and_64(union atomic_ptr_64 ptr, union atomic_val_64 val, int memorder)
{
    (void)memorder;
    latomic_fetch_and_n(ptr.ull_ptr, val.ull);
}
#endif /* latomic_and_64 */

/* latomic_or */

#ifndef latomic_or_32
void
latomic_or_32(union atomic_ptr_32 ptr, union atomic_val_32 val, int memorder)
{
    (void)memorder;
    latomic_fetch_or_n(ptr.ui_ptr, val.ui);
}
#endif /* latomic_or_32 */

#ifndef latomic_or_64
void
latomic_or_64(union atomic_ptr_64 ptr, union atomic_val_64 val, int memorder)
{
    (void)memorder;
    latomic_fetch_or_n(ptr.ull_ptr, val.ull);
}
#endif /* latomic_or_64 */

/* latomic_xor */

#ifndef latomic_xor_32
void
latomic_xor_32(union atomic_ptr_32 ptr, union atomic_val_32 val, int memorder)
{
    (void)memorder;
    latomic_fetch_xor_n(ptr.ui_ptr, val.ui);
}
#endif /* latomic_xor_32 */

#ifndef latomic_xor_64
void
latomic_xor_64(union atomic_ptr_64 ptr, union atomic_val_64 val, int memorder)
{
    (void)memorder;
    latomic_fetch_xor_n(ptr.ull_ptr, val.ull);
}
#endif /* latomic_xor_64 */
