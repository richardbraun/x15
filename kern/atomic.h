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
 * Type-generic memory-model aware atomic operations.
 *
 * For portability reasons, this interface restricts atomic operation
 * sizes to 32-bit and 64-bit.
 *
 * Some configurations may not support 64-bit operations. Check if the
 * ATOMIC_HAVE_64B_OPS macro is defined to find out.
 *
 * TODO Replace mentions of "memory barriers" throughout the code with
 * C11 memory model terminology.
 */

#ifndef KERN_ATOMIC_H
#define KERN_ATOMIC_H

#include <stdbool.h>

#include <machine/atomic.h>

/*
 * Supported memory orders.
 */
#define ATOMIC_RELAXED  __ATOMIC_RELAXED
#define ATOMIC_CONSUME  __ATOMIC_CONSUME
#define ATOMIC_ACQUIRE  __ATOMIC_ACQUIRE
#define ATOMIC_RELEASE  __ATOMIC_RELEASE
#define ATOMIC_ACQ_REL  __ATOMIC_ACQ_REL
#define ATOMIC_SEQ_CST  __ATOMIC_SEQ_CST

#include <kern/atomic_i.h>

#define atomic_load(ptr, memorder) \
((typeof(*(ptr)))atomic_select(ptr, load)(ptr, memorder))

#define atomic_store(ptr, val, memorder) \
atomic_select(ptr, store)(ptr, val, memorder)

/*
 * For compare-and-swap, deviate a little from the standard, and only
 * return the value before the comparison, leaving it up to the user to
 * determine whether the swap was actually performed or not.
 *
 * Also, note that the memory order in case of failure is relaxed. This is
 * because atomic CAS is typically used in a loop. However, if a different
 * code path is taken on failure (rather than retrying), then the user
 * should be aware that a memory fence might be necessary.
 */
#define atomic_cas(ptr, oval, nval, memorder) \
((typeof(*(ptr)))atomic_select(ptr, cas)(ptr, oval, nval, memorder))

#define atomic_swap(ptr, val, memorder) \
((typeof(*(ptr)))atomic_select(ptr, swap)(ptr, val, memorder))

#define atomic_fetch_add(ptr, val, memorder) \
((typeof(*(ptr)))atomic_select(ptr, fetch_add)(ptr, val, memorder))

#define atomic_fetch_sub(ptr, val, memorder) \
((typeof(*(ptr)))atomic_select(ptr, fetch_sub)(ptr, val, memorder))

#define atomic_fetch_and(ptr, val, memorder) \
((typeof(*(ptr)))atomic_select(ptr, fetch_and)(ptr, val, memorder))

#define atomic_fetch_or(ptr, val, memorder) \
((typeof(*(ptr)))atomic_select(ptr, fetch_or)(ptr, val, memorder))

#define atomic_fetch_xor(ptr, val, memorder) \
((typeof(*(ptr)))atomic_select(ptr, fetch_xor)(ptr, val, memorder))

#define atomic_add(ptr, val, memorder) \
atomic_select(ptr, add)(ptr, val, memorder)

#define atomic_sub(ptr, val, memorder) \
atomic_select(ptr, sub)(ptr, val, memorder)

#define atomic_and(ptr, val, memorder) \
atomic_select(ptr, and)(ptr, val, memorder)

#define atomic_or(ptr, val, memorder) \
atomic_select(ptr, or)(ptr, val, memorder)

#define atomic_xor(ptr, val, memorder) \
atomic_select(ptr, xor)(ptr, val, memorder)

#define atomic_fence(memorder) __atomic_thread_fence(memorder)

#endif /* KERN_ATOMIC_H */
