/*
 * Copyright (c) 2012-2017 Richard Braun.
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
 * Atomic operations.
 *
 * When referring to atomic operations, "local" means processor-local.
 */

#ifndef _X86_ATOMIC_H
#define _X86_ATOMIC_H

#include <stdint.h>

#define ATOMIC_ADD(ptr, delta)                              \
    asm volatile("lock add %1, %0"                          \
                 : "+m" (*(ptr))                            \
                 : "r" (delta))

#define ATOMIC_FETCHADD(ptr, oldval, delta)                 \
    asm volatile("lock xadd %1, %0"                         \
                 : "+m" (*(ptr)), "=r" (oldval)             \
                 : "1" (delta)                              \
                 : "memory")

#define ATOMIC_AND(ptr, bits)                               \
    asm volatile("lock and %1, %0"                          \
                 : "+m" (*(ptr))                            \
                 : "r" (bits))

#define ATOMIC_OR(ptr, bits)                                \
    asm volatile("lock or %1, %0"                           \
                 : "+m" (*(ptr))                            \
                 : "r" (bits))

#define ATOMIC_XOR(ptr, bits)                               \
    asm volatile("lock xor %1, %0"                          \
                 : "+m" (*(ptr))                            \
                 : "r" (bits))

/* The xchg instruction doesn't need a lock prefix */
#define ATOMIC_SWAP(ptr, oldval, newval)                    \
    asm volatile("xchg %1, %0"                              \
                 : "+m" (*(ptr)), "=r" (oldval)             \
                 : "1" (newval)                             \
                 : "memory")

#define ATOMIC_CAS(ptr, oldval, predicate, newval)          \
    asm volatile("lock cmpxchg %3, %0"                      \
                 : "+m" (*(ptr)), "=a" (oldval)             \
                 : "1" (predicate), "r" (newval)            \
                 : "memory")

#define ATOMIC_LOCAL_ADD(ptr, delta)                        \
    asm volatile("add %1, %0"                               \
                 : "+m" (*(ptr))                            \
                 : "r" (delta))

#define ATOMIC_LOCAL_FETCHADD(ptr, oldval, delta)           \
    asm volatile("xadd %1, %0"                              \
                 : "+m" (*(ptr)), "=r" (oldval)             \
                 : "1" (delta)                              \
                 : "memory")

#define ATOMIC_LOCAL_AND(ptr, bits)                         \
    asm volatile("and %1, %0"                               \
                 : "+m" (*(ptr))                            \
                 : "r" (bits))

#define ATOMIC_LOCAL_OR(ptr, bits)                          \
    asm volatile("or %1, %0"                                \
                 : "+m" (*(ptr))                            \
                 : "r" (bits))

#define ATOMIC_LOCAL_XOR(ptr, bits)                         \
    asm volatile("xor %1, %0"                               \
                 : "+m" (*(ptr))                            \
                 : "r" (bits))

/* The xchg instruction implies a lock prefix */
#define ATOMIC_LOCAL_SWAP(ptr, oldval, newval)              \
    asm volatile("xchg %1, %0"                              \
                 : "+m" (*(ptr)), "=r" (oldval)             \
                 : "1" (newval)                             \
                 : "memory")

#define ATOMIC_LOCAL_CAS(ptr, oldval, predicate, newval)    \
    asm volatile("cmpxchg %3, %0"                           \
                 : "+m" (*(ptr)), "=a" (oldval)             \
                 : "1" (predicate), "r" (newval)            \
                 : "memory")

static inline void
atomic_add_uint(volatile unsigned int *ptr, int delta)
{
    ATOMIC_ADD(ptr, delta);
}

/*
 * Implies a full memory barrier.
 */
static inline unsigned int
atomic_fetchadd_uint(volatile unsigned int *ptr, int delta)
{
    unsigned int oldval;

    ATOMIC_FETCHADD(ptr, oldval, delta);
    return oldval;
}

static inline void
atomic_and_uint(volatile unsigned int *ptr, unsigned int bits)
{
    ATOMIC_AND(ptr, bits);
}

static inline void
atomic_or_uint(volatile unsigned int *ptr, unsigned int bits)
{
    ATOMIC_OR(ptr, bits);
}

static inline void
atomic_xor_uint(volatile unsigned int *ptr, unsigned int bits)
{
    ATOMIC_XOR(ptr, bits);
}

/*
 * Implies a full memory barrier.
 */
static inline unsigned int
atomic_swap_uint(volatile unsigned int *ptr, unsigned int newval)
{
    unsigned int oldval;

    ATOMIC_SWAP(ptr, oldval, newval);
    return oldval;
}

/*
 * Implies a full memory barrier.
 */
static inline unsigned int
atomic_cas_uint(volatile unsigned int *ptr, unsigned int predicate,
                unsigned int newval)
{
    unsigned int oldval;

    ATOMIC_CAS(ptr, oldval, predicate, newval);
    return oldval;
}

static inline void
atomic_local_add_uint(volatile unsigned int *ptr, int delta)
{
    ATOMIC_LOCAL_ADD(ptr, delta);
}

/*
 * Implies a compiler barrier.
 */
static inline unsigned int
atomic_local_fetchadd_uint(volatile unsigned int *ptr, int delta)
{
    unsigned int oldval;

    ATOMIC_LOCAL_FETCHADD(ptr, oldval, delta);
    return oldval;
}

static inline void
atomic_local_and_uint(volatile unsigned int *ptr, unsigned int bits)
{
    ATOMIC_LOCAL_AND(ptr, bits);
}

static inline void
atomic_local_or_uint(volatile unsigned int *ptr, unsigned int bits)
{
    ATOMIC_LOCAL_OR(ptr, bits);
}

static inline void
atomic_local_xor_uint(volatile unsigned int *ptr, unsigned int bits)
{
    ATOMIC_LOCAL_XOR(ptr, bits);
}

/*
 * Implies a compiler barrier.
 */
static inline unsigned int
atomic_local_swap_uint(volatile unsigned int *ptr, unsigned int newval)
{
    unsigned int oldval;

    ATOMIC_LOCAL_SWAP(ptr, oldval, newval);
    return oldval;
}

/*
 * Implies a compiler barrier.
 */
static inline unsigned int
atomic_local_cas_uint(volatile unsigned int *ptr, unsigned int predicate,
                      unsigned int newval)
{
    unsigned int oldval;

    ATOMIC_LOCAL_CAS(ptr, oldval, predicate, newval);
    return oldval;
}

static inline void
atomic_add_ulong(volatile unsigned long *ptr, long delta)
{
    ATOMIC_ADD(ptr, delta);
}

/*
 * Implies a full memory barrier.
 */
static inline unsigned long
atomic_fetchadd_ulong(volatile unsigned long *ptr, long delta)
{
    unsigned long oldval;

    ATOMIC_FETCHADD(ptr, oldval, delta);
    return oldval;
}

static inline void
atomic_and_ulong(volatile unsigned long *ptr, unsigned long bits)
{
    ATOMIC_AND(ptr, bits);
}

static inline void
atomic_or_ulong(volatile unsigned long *ptr, unsigned long bits)
{
    ATOMIC_OR(ptr, bits);
}

static inline void
atomic_xor_ulong(volatile unsigned long *ptr, unsigned long bits)
{
    ATOMIC_XOR(ptr, bits);
}

/*
 * Implies a full memory barrier.
 */
static inline unsigned long
atomic_swap_ulong(volatile unsigned long *ptr, unsigned long newval)
{
    unsigned long oldval;

    ATOMIC_SWAP(ptr, oldval, newval);
    return oldval;
}

/*
 * Implies a full memory barrier.
 */
static inline unsigned long
atomic_cas_ulong(volatile unsigned long *ptr, unsigned long predicate,
                 unsigned long newval)
{
    unsigned long oldval;

    ATOMIC_CAS(ptr, oldval, predicate, newval);
    return oldval;
}

static inline void
atomic_local_add_ulong(volatile unsigned long *ptr, long delta)
{
    ATOMIC_LOCAL_ADD(ptr, delta);
}

/*
 * Implies a compiler barrier.
 */
static inline unsigned long
atomic_local_fetchadd_ulong(volatile unsigned long *ptr, long delta)
{
    unsigned long oldval;

    ATOMIC_LOCAL_FETCHADD(ptr, oldval, delta);
    return oldval;
}

static inline void
atomic_local_and_ulong(volatile unsigned long *ptr, unsigned long bits)
{
    ATOMIC_LOCAL_AND(ptr, bits);
}

static inline void
atomic_local_or_ulong(volatile unsigned long *ptr, unsigned long bits)
{
    ATOMIC_LOCAL_OR(ptr, bits);
}

static inline void
atomic_local_xor_ulong(volatile unsigned long *ptr, unsigned long bits)
{
    ATOMIC_LOCAL_XOR(ptr, bits);
}

/*
 * Implies a compiler barrier.
 */
static inline unsigned long
atomic_local_swap_ulong(volatile unsigned long *ptr, unsigned long newval)
{
    unsigned long oldval;

    ATOMIC_LOCAL_SWAP(ptr, oldval, newval);
    return oldval;
}

/*
 * Implies a compiler barrier.
 */
static inline unsigned long
atomic_local_cas_ulong(volatile unsigned long *ptr, unsigned long predicate,
                       unsigned long newval)
{
    unsigned long oldval;

    ATOMIC_LOCAL_CAS(ptr, oldval, predicate, newval);
    return oldval;
}

static inline void
atomic_add_uintptr(volatile uintptr_t *ptr, intptr_t delta)
{
    ATOMIC_ADD(ptr, delta);
}

/*
 * Implies a full memory barrier.
 */
static inline uintptr_t
atomic_fetchadd_uintptr(volatile uintptr_t *ptr, intptr_t delta)
{
    uintptr_t oldval;

    ATOMIC_FETCHADD(ptr, oldval, delta);
    return oldval;
}

static inline void
atomic_and_uintptr(volatile uintptr_t *ptr, uintptr_t bits)
{
    ATOMIC_AND(ptr, bits);
}

static inline void
atomic_or_uintptr(volatile uintptr_t *ptr, uintptr_t bits)
{
    ATOMIC_OR(ptr, bits);
}

static inline void
atomic_xor_uintptr(volatile uintptr_t *ptr, uintptr_t bits)
{
    ATOMIC_XOR(ptr, bits);
}

/*
 * Implies a full memory barrier.
 */
static inline uintptr_t
atomic_swap_uintptr(volatile uintptr_t *ptr, uintptr_t newval)
{
    uintptr_t oldval;

    ATOMIC_SWAP(ptr, oldval, newval);
    return oldval;
}

/*
 * Implies a full memory barrier.
 */
static inline uintptr_t
atomic_cas_uintptr(volatile uintptr_t *ptr, uintptr_t predicate,
                   uintptr_t newval)
{
    uintptr_t oldval;

    ATOMIC_CAS(ptr, oldval, predicate, newval);
    return oldval;
}

static inline void
atomic_local_add_uintptr(volatile uintptr_t *ptr, intptr_t delta)
{
    ATOMIC_LOCAL_ADD(ptr, delta);
}

/*
 * Implies a compiler barrier.
 */
static inline uintptr_t
atomic_local_fetchadd_uintptr(volatile uintptr_t *ptr, intptr_t delta)
{
    uintptr_t oldval;

    ATOMIC_LOCAL_FETCHADD(ptr, oldval, delta);
    return oldval;
}

static inline void
atomic_local_and_uintptr(volatile uintptr_t *ptr, uintptr_t bits)
{
    ATOMIC_LOCAL_AND(ptr, bits);
}

static inline void
atomic_local_or_uintptr(volatile uintptr_t *ptr, uintptr_t bits)
{
    ATOMIC_LOCAL_OR(ptr, bits);
}

static inline void
atomic_local_xor_uintptr(volatile uintptr_t *ptr, uintptr_t bits)
{
    ATOMIC_LOCAL_XOR(ptr, bits);
}

/*
 * Implies a compiler barrier.
 */
static inline uintptr_t
atomic_local_swap_uintptr(volatile uintptr_t *ptr, uintptr_t newval)
{
    uintptr_t oldval;

    ATOMIC_LOCAL_SWAP(ptr, oldval, newval);
    return oldval;
}

/*
 * Implies a compiler barrier.
 */
static inline uintptr_t
atomic_local_cas_uintptr(volatile uintptr_t *ptr, uintptr_t predicate,
                         uintptr_t newval)
{
    uintptr_t oldval;

    ATOMIC_LOCAL_CAS(ptr, oldval, predicate, newval);
    return oldval;
}

#endif /* _X86_ATOMIC_H */
