/*
 * Copyright (c) 2012 Richard Braun.
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
 */

#ifndef _X86_ATOMIC_H
#define _X86_ATOMIC_H

static inline void
atomic_add(volatile unsigned long *ptr, long delta)
{
    asm volatile("lock add %1, %0"
                 : "+m" (*ptr)
                 : "r" (delta));
}

static inline void
atomic_and(volatile unsigned long *ptr, unsigned long bits)
{
    asm volatile("lock and %1, %0"
                 : "+m" (*ptr)
                 : "r" (bits));
}

static inline void
atomic_or(volatile unsigned long *ptr, unsigned long bits)
{
    asm volatile("lock or %1, %0"
                 : "+m" (*ptr)
                 : "r" (bits));
}

/*
 * Implies a full memory barrier.
 */
static inline unsigned long
atomic_swap(volatile unsigned long *ptr, unsigned long newval)
{
    unsigned long prev;

    /* The xchg instruction doesn't need a lock prefix */
    asm volatile("xchg %1, %0"
                 : "+m" (*ptr), "=r" (prev)
                 : "1" (newval)
                 : "memory");

    return prev;
}

/*
 * Implies a full memory barrier.
 */
static inline unsigned long
atomic_cas(volatile unsigned long *ptr, unsigned long oldval,
           unsigned long newval)
{
    unsigned long prev;

    asm volatile("lock cmpxchg %3, %0"
                 : "+m" (*ptr), "=a" (prev)
                 : "1" (oldval), "r" (newval)
                 : "memory");

    return prev;
}

#endif /* _X86_ATOMIC_H */
