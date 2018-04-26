/*
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
 * Isolated type definition used to avoid inclusion circular dependencies.
 */

#ifndef KERN_ATOMIC_TYPES_H
#define KERN_ATOMIC_TYPES_H

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

#endif /* __LP64__ */

#endif /* KERN_ATOMIC_TYPES_H */
