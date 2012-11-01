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
 * Memory barriers.
 *
 * Keep in mind that memory barriers only act on the ordering of loads and
 * stores between internal processor queues and their caches. In particular,
 * it doesn't imply a store is complete after the barrier has completed, only
 * that other processors will see a new value thanks to the cache coherency
 * protocol. Memory barriers aren't suitable for device communication.
 */

#ifndef _X86_MB_H
#define _X86_MB_H

#ifdef __LP64__

static inline void
mb_sync(void)
{
    asm volatile("mfence" : : : "memory");
}

static inline void
mb_load(void)
{
    asm volatile("lfence" : : : "memory");
}

static inline void
mb_store(void)
{
    asm volatile("sfence" : : : "memory");
}

#else /* __LP64__ */

static inline void
mb_sync(void)
{
    asm volatile("lock addl $0, 0(%%esp)" : : : "cc", "memory");
}

static inline void
mb_load(void)
{
    mb_sync();
}

static inline void
mb_store(void)
{
    mb_sync();
}

#endif /* __LP64__ */

#endif /* _X86_MB_H */
