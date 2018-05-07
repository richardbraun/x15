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
 * This test makes sure that atomic operations behave at least as their
 * non-atomic counterpart. It doesn't actually test the atomicity of the
 * operations, but rather helps check that the generated code matches
 * expectations for the target configuration.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <kern/atomic.h>
#include <kern/error.h>
#include <kern/init.h>
#include <kern/log.h>
#include <kern/macros.h>
#include <test/test.h>

#ifdef CONFIG_TEST_MODULE_ATOMIC_64
typedef uint64_t test_int_t;
#else
typedef unsigned long test_int_t;
#endif

/*
 * Don't make this variable private, so that the compiler may not assume
 * that all accesses are known, which forces it to generate access
 * instructions for it. This only works when building without LTO.
 */
test_int_t test_n;

/*
 * Prevent these functions from being inlined in order to make the generated
 * code easy to find and review.
 */

static __noinline test_int_t
test_atomic_load(test_int_t *n)
{
    return atomic_load(n, ATOMIC_RELAXED);
}

static __noinline void
test_atomic_store(test_int_t *n, test_int_t val)
{
    atomic_store(n, val, ATOMIC_RELAXED);
}

static __noinline test_int_t
test_atomic_cas(test_int_t *n, test_int_t oval, test_int_t nval)
{
    return atomic_cas(n, oval, nval, ATOMIC_RELAXED);
}

static __noinline test_int_t
test_atomic_swap(test_int_t *n, test_int_t val)
{
    return atomic_swap(n, val, ATOMIC_RELAXED);
}

static __noinline test_int_t
test_atomic_fetch_add(test_int_t *n, test_int_t val)
{
    return atomic_fetch_add(n, val, ATOMIC_RELAXED);
}

static __noinline test_int_t
test_atomic_fetch_sub(test_int_t *n, test_int_t val)
{
    return atomic_fetch_sub(n, val, ATOMIC_RELAXED);
}

static __noinline test_int_t
test_atomic_fetch_and(test_int_t *n, test_int_t val)
{
    return atomic_fetch_and(n, val, ATOMIC_RELAXED);
}

static __noinline test_int_t
test_atomic_fetch_or(test_int_t *n, test_int_t val)
{
    return atomic_fetch_or(n, val, ATOMIC_RELAXED);
}

static __noinline test_int_t
test_atomic_fetch_xor(test_int_t *n, test_int_t val)
{
    return atomic_fetch_xor(n, val, ATOMIC_RELAXED);
}

static __noinline void
test_atomic_add(test_int_t *n, test_int_t val)
{
    atomic_add(n, val, ATOMIC_RELAXED);
}

static __noinline void
test_atomic_sub(test_int_t *n, test_int_t val)
{
    atomic_sub(n, val, ATOMIC_RELAXED);
}

static __noinline void
test_atomic_and(test_int_t *n, test_int_t val)
{
    atomic_and(n, val, ATOMIC_RELAXED);
}

static __noinline void
test_atomic_or(test_int_t *n, test_int_t val)
{
    atomic_or(n, val, ATOMIC_RELAXED);
}

static __noinline void
test_atomic_xor(test_int_t *n, test_int_t val)
{
    atomic_xor(n, val, ATOMIC_RELAXED);
}

static void
test_check_n(test_int_t val, const char *fn)
{
    volatile test_int_t *ptr;
    int error;

    ptr = &test_n;
    error = (val == *ptr) ? 0 : EINVAL;
    error_check(error, fn);
}

static void
test_load(void)
{
    test_int_t n;

    n = test_atomic_load(&test_n);
    test_check_n(n, __func__);
}

static void
test_store(void)
{
    test_int_t val;

    val = 0x123;
    test_atomic_store(&test_n, val);
    test_check_n(val, __func__);
}

static void
test_cas_match(void)
{
    test_int_t prev, oval, nval;
    int error;

    oval = 0;
    nval = 0x123;
    test_n = oval;
    prev = test_atomic_cas(&test_n, oval, nval);
    error = (prev == oval) ? 0 : EINVAL;
    error_check(error, __func__);
    test_check_n(nval, __func__);
}

static void
test_cas_nomatch(void)
{
    test_int_t prev, oval, nval;
    int error;

    oval = 0;
    nval = 0x123;
    test_n = oval;
    prev = test_atomic_cas(&test_n, oval + 1, nval);
    error = (prev == oval) ? 0 : EINVAL;
    error_check(error, __func__);
    test_check_n(oval, __func__);
}

static void
test_swap(void)
{
    test_int_t prev, oval, nval;
    int error;

    oval = 0;
    nval = 0x123;
    test_n = oval;
    prev = test_atomic_swap(&test_n, nval);
    error = (prev == oval) ? 0 : EINVAL;
    error_check(error, __func__);
    test_check_n(nval, __func__);
}

static void
test_fetch_add(void)
{
    test_int_t prev, oval, delta;
    int error;

    oval = 0x123;
    delta = 0x456;
    test_n = oval;
    prev = test_atomic_fetch_add(&test_n, delta);
    error = (prev == oval) ? 0 : EINVAL;
    error_check(error, __func__);
    test_check_n(oval + delta, __func__);
}

static void
test_fetch_sub(void)
{
    test_int_t prev, oval, delta;
    int error;

    oval = 0x123;
    delta = 0x456;
    test_n = oval;
    prev = test_atomic_fetch_sub(&test_n, delta);
    error = (prev == oval) ? 0 : EINVAL;
    error_check(error, __func__);
    test_check_n(oval - delta, __func__);
}

static void
test_fetch_and(void)
{
    test_int_t prev, oval, delta;
    int error;

    oval = 0x123;
    delta = 0x456;
    test_n = oval;
    prev = test_atomic_fetch_and(&test_n, delta);
    error = (prev == oval) ? 0 : EINVAL;
    error_check(error, __func__);
    test_check_n(oval & delta, __func__);
}

static void
test_fetch_or(void)
{
    test_int_t prev, oval, delta;
    int error;

    oval = 0x123;
    delta = 0x456;
    test_n = oval;
    prev = test_atomic_fetch_or(&test_n, delta);
    error = (prev == oval) ? 0 : EINVAL;
    error_check(error, __func__);
    test_check_n(oval | delta, __func__);
}

static void
test_fetch_xor(void)
{
    test_int_t prev, oval, delta;
    int error;

    oval = 0x123;
    delta = 0x456;
    test_n = oval;
    prev = test_atomic_fetch_xor(&test_n, delta);
    error = (prev == oval) ? 0 : EINVAL;
    error_check(error, __func__);
    test_check_n(oval ^ delta, __func__);
}

static void
test_add(void)
{
    test_int_t oval, delta;

    oval = 0x123;
    delta = 0x456;
    test_n = oval;
    test_atomic_add(&test_n, delta);
    test_check_n(oval + delta, __func__);
}

static void
test_sub(void)
{
    test_int_t oval, delta;

    oval = 0x123;
    delta = 0x456;
    test_n = oval;
    test_atomic_sub(&test_n, delta);
    test_check_n(oval - delta, __func__);
}

static void
test_and(void)
{
    test_int_t oval, delta;

    oval = 0x123;
    delta = 0x456;
    test_n = oval;
    test_atomic_and(&test_n, delta);
    test_check_n(oval & delta, __func__);
}

static void
test_or(void)
{
    test_int_t oval, delta;

    oval = 0x123;
    delta = 0x456;
    test_n = oval;
    test_atomic_or(&test_n, delta);
    test_check_n(oval | delta, __func__);
}

static void
test_xor(void)
{
    test_int_t oval, delta;

    oval = 0x123;
    delta = 0x456;
    test_n = oval;
    test_atomic_xor(&test_n, delta);
    test_check_n(oval ^ delta, __func__);
}

void __init
test_setup(void)
{
    test_load();
    test_store();
    test_cas_match();
    test_cas_nomatch();
    test_swap();
    test_fetch_add();
    test_fetch_sub();
    test_fetch_and();
    test_fetch_or();
    test_fetch_xor();
    test_add();
    test_sub();
    test_and();
    test_or();
    test_xor();
    log_info("test: done");
}
