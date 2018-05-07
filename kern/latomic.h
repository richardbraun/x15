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
 * CPU-local atomic operations.
 *
 * The latomic module provides operations that are "atomic on the local
 * processor", i.e. interrupt-safe. Its interface is similar in spirit
 * and purpose to that of the atomic module, and it can transparently
 * replace it on single-processor configurations.
 *
 * Note that the only operations guaranteed to be truely atomic, i.e.
 * to completely execute in a single atomic instruction, are loads and
 * stores. All other operations may be implemented with multiple
 * instructions, possibly disabling interrupts. The rationale is that
 * atomic loads and stores are required for some types of access, such
 * as memory-mapped device registers, while other operations only require
 * interrupt safety.
 *
 * This header provides a generic implementation. Architectures can
 * individually override any of the operations provided by this module.
 */

#ifndef KERN_LATOMIC_H
#define KERN_LATOMIC_H

#include <assert.h>

#include <kern/macros.h>

/*
 * Memory orders for local atomic operations.
 *
 * These work like those in the atomic module, but are implemented
 * with simple compiler barriers instead of full memory fences.
 */
#define LATOMIC_RELAXED __ATOMIC_RELAXED
#define LATOMIC_ACQUIRE __ATOMIC_ACQUIRE
#define LATOMIC_RELEASE __ATOMIC_RELEASE
#define LATOMIC_ACQ_REL __ATOMIC_ACQ_REL
#define LATOMIC_SEQ_CST __ATOMIC_SEQ_CST

#include <kern/latomic_i.h>

#define latomic_load(ptr, memorder)                                         \
MACRO_BEGIN                                                                 \
    assert(latomic_ptr_aligned(ptr));                                       \
    ((typeof(*(ptr)))latomic_select(ptr, load)(ptr, memorder));             \
MACRO_END

#define latomic_store(ptr, val, memorder)                                   \
MACRO_BEGIN                                                                 \
    assert(latomic_ptr_aligned(ptr));                                       \
    latomic_select(ptr, store)(ptr, val, memorder);                         \
MACRO_END

#define latomic_swap(ptr, val, memorder)                                    \
MACRO_BEGIN                                                                 \
    assert(latomic_ptr_aligned(ptr));                                       \
    ((typeof(*(ptr)))latomic_select(ptr, swap)(ptr, val, memorder));        \
MACRO_END

#define latomic_cas(ptr, oval, nval, memorder)                              \
MACRO_BEGIN                                                                 \
    assert(latomic_ptr_aligned(ptr));                                       \
    ((typeof(*(ptr)))latomic_select(ptr, cas)(ptr, oval, nval, memorder));  \
MACRO_END

#define latomic_fetch_add(ptr, val, memorder)                               \
MACRO_BEGIN                                                                 \
    assert(latomic_ptr_aligned(ptr));                                       \
    ((typeof(*(ptr)))latomic_select(ptr, fetch_add)(ptr, val, memorder));   \
MACRO_END

#define latomic_fetch_sub(ptr, val, memorder)                               \
MACRO_BEGIN                                                                 \
    assert(latomic_ptr_aligned(ptr));                                       \
    ((typeof(*(ptr)))latomic_select(ptr, fetch_sub)(ptr, val, memorder));   \
MACRO_END

#define latomic_fetch_and(ptr, val, memorder)                               \
MACRO_BEGIN                                                                 \
    assert(latomic_ptr_aligned(ptr));                                       \
    ((typeof(*(ptr)))latomic_select(ptr, fetch_and)(ptr, val, memorder));   \
MACRO_END

#define latomic_fetch_or(ptr, val, memorder)                                \
MACRO_BEGIN                                                                 \
    assert(latomic_ptr_aligned(ptr));                                       \
    ((typeof(*(ptr)))latomic_select(ptr, fetch_or)(ptr, val, memorder));    \
MACRO_END

#define latomic_fetch_xor(ptr, val, memorder)                               \
MACRO_BEGIN                                                                 \
    assert(latomic_ptr_aligned(ptr));                                       \
    ((typeof(*(ptr)))latomic_select(ptr, fetch_xor)(ptr, val, memorder));   \
MACRO_END

#define latomic_add(ptr, val, memorder)                                     \
MACRO_BEGIN                                                                 \
    assert(latomic_ptr_aligned(ptr));                                       \
    latomic_select(ptr, add)(ptr, val, memorder);                           \
MACRO_END

#define latomic_sub(ptr, val, memorder)                                     \
MACRO_BEGIN                                                                 \
    assert(latomic_ptr_aligned(ptr));                                       \
    latomic_select(ptr, sub)(ptr, val, memorder);                           \
MACRO_END

#define latomic_and(ptr, val, memorder)                                     \
MACRO_BEGIN                                                                 \
    assert(latomic_ptr_aligned(ptr));                                       \
    latomic_select(ptr, and)(ptr, val, memorder);                           \
MACRO_END

#define latomic_or(ptr, val, memorder)                                      \
MACRO_BEGIN                                                                 \
    assert(latomic_ptr_aligned(ptr));                                       \
    latomic_select(ptr, or)(ptr, val, memorder);                            \
MACRO_END

#define latomic_xor(ptr, val, memorder)                                     \
MACRO_BEGIN                                                                 \
    assert(latomic_ptr_aligned(ptr));                                       \
    latomic_select(ptr, xor)(ptr, val, memorder);                           \
MACRO_END

#define latomic_fence(memorder)             \
MACRO_BEGIN                                 \
    assert(memorder != LATOMIC_RELAXED);    \
    barrier();                              \
MACRO_END

#endif /* KERN_LATOMIC_H */
