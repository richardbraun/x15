/*
 * Copyright (c) 2010-2017 Richard Braun.
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
 * Hash functions for integers and strings.
 *
 * Integer hashing follows Thomas Wang's paper about his 32/64-bits mix
 * functions :
 * - https://gist.github.com/badboy/6267743
 *
 * String hashing uses a variant of the djb2 algorithm with k=31, as in
 * the implementation of the hashCode() method of the Java String class :
 * - http://www.javamex.com/tutorials/collections/hash_function_technical.shtml
 *
 * Note that this algorithm isn't suitable to obtain usable 64-bits hashes
 * and is expected to only serve as an array index producer.
 *
 * These functions all have a bits parameter that indicates the number of
 * relevant bits the caller is interested in. When returning a hash, its
 * value must be truncated so that it can fit in the requested bit size.
 * It can be used by the implementation to select high or low bits, depending
 * on their relative randomness. To get complete, unmasked hashes, use the
 * HASH_ALLBITS macro.
 */

#ifndef _KERN_HASH_H
#define _KERN_HASH_H

#include <stdint.h>
#include <string.h>

#include <kern/assert.h>

#ifdef __LP64__
#define HASH_ALLBITS 64
#define hash_long(n, bits) hash_int64(n, bits)
#else /* __LP64__ */
static_assert(sizeof(long) == 4, "unsupported data model");
#define HASH_ALLBITS 32
#define hash_long(n, bits) hash_int32(n, bits)
#endif

static inline uint32_t
hash_int32(uint32_t n, unsigned int bits)
{
    uint32_t hash;

    hash = n;
    hash = ~hash + (hash << 15);
    hash ^= (hash >> 12);
    hash += (hash << 2);
    hash ^= (hash >> 4);
    hash += (hash << 3) + (hash << 11);
    hash ^= (hash >> 16);

    return hash >> (32 - bits);
}

static inline uint64_t
hash_int64(uint64_t n, unsigned int bits)
{
    uint64_t hash;

    hash = n;
    hash = ~hash + (hash << 21);
    hash ^= (hash >> 24);
    hash += (hash << 3) + (hash << 8);
    hash ^= (hash >> 14);
    hash += (hash << 2) + (hash << 4);
    hash ^= (hash >> 28);
    hash += (hash << 31);

    return hash >> (64 - bits);
}

static inline uintptr_t
hash_ptr(const void *ptr, unsigned int bits)
{
    if (sizeof(uintptr_t) == 8) {
        return hash_int64((uintptr_t)ptr, bits);
    } else {
        return hash_int32((uintptr_t)ptr, bits);
    }
}

static inline unsigned long
hash_str(const char *str, unsigned int bits)
{
    unsigned long hash;
    char c;

    for (hash = 0; (c = *str) != '\0'; str++) {
        hash = ((hash << 5) - hash) + c;
    }

    return hash & ((1 << bits) - 1);
}

#endif /* _KERN_HASH_H */
