/*
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
 */

#ifndef _KERN_ATOMIC_H
#define _KERN_ATOMIC_H

#include <stdbool.h>

#include <kern/macros.h>
#include <machine/atomic.h>

/*
 * Supported memory orders.
 *
 * Note that the consume order is aliased to relaxed. This assumes that
 * all supported processors respect data dependencies. The rationale is
 * that the definition for the consume order is confusing enough that
 * most compilers alias it to acquire, which forces the generation of
 * memory barrier instructions even when they're not really needed.
 * Since there is currently no processor where using consume or relaxed
 * would produce different code, it is safe to establish that alias.
 * It serves as explicit documentation for code review, and will easily
 * be replaced with the true consume order once compiler support becomes
 * efficient and reliable.
 */
#define ATOMIC_RELAXED   __ATOMIC_RELAXED
#define ATOMIC_CONSUME   __ATOMIC_RELAXED
#define ATOMIC_ACQUIRE   __ATOMIC_ACQUIRE
#define ATOMIC_RELEASE   __ATOMIC_RELEASE
#define ATOMIC_ACQ_REL   __ATOMIC_ACQ_REL
#define ATOMIC_SEQ_CST   __ATOMIC_SEQ_CST

/*
 * Type-generic atomic operations.
 */
#define atomic_fetch_add(ptr, val, mo)  __atomic_fetch_add(ptr, val, mo)

#define atomic_fetch_sub(ptr, val, mo)  __atomic_fetch_sub(ptr, val, mo)

#define atomic_fetch_and(ptr, val, mo)  __atomic_fetch_and(ptr, val, mo)

#define atomic_fetch_or(ptr, val, mo)   __atomic_fetch_or(ptr, val, mo)

#define atomic_fetch_xor(ptr, val, mo)  __atomic_fetch_xor(ptr, val, mo)

#define atomic_add(ptr, val, mo)        (void)__atomic_add_fetch(ptr, val, mo)

#define atomic_sub(ptr, val, mo)        (void)__atomic_sub_fetch(ptr, val, mo)

#define atomic_and(ptr, val, mo)        (void)__atomic_and_fetch(ptr, val, mo)

#define atomic_or(ptr, val, mo)         (void)__atomic_or_fetch(ptr, val, mo)

#define atomic_xor(ptr, val, mo)        (void)__atomic_xor_fetch(ptr, val, mo)

#define atomic_swap(ptr, val, mo)       __atomic_exchange_n(ptr, val, mo)

/*
 * For compare-and-swap, deviate a little from the standard, and only
 * return the value before the comparison, leaving it up to the user to
 * determine whether the swap was actually performed or not.
 *
 * Also, note that the memory order in case of failure is relaxed. This is
 * because atomic CAS is typically used in a loop. However, if a different
 * code path is taken on failure (rather than retrying), then the user
 * should be aware that a memory fence might be necessary.
 *
 * Finally, although a local variable isn't strictly needed for the new
 * value, some compilers seem to have trouble when all parameters don't
 * have the same type.
 */
#define atomic_cas(ptr, oval, nval, mo)                           \
MACRO_BEGIN                                                       \
    typeof(*(ptr)) ___oval, ___nval;                              \
                                                                  \
    ___oval = (oval);                                             \
    ___nval = (nval);                                             \
    __atomic_compare_exchange_n(ptr, &___oval, ___nval, false,    \
                                mo, ATOMIC_RELAXED);              \
    ___oval;                                                      \
MACRO_END

/*
 * Some architectures may need specific definitions for loads and stores,
 * in order to prevent the compiler from emitting unsupported instructions.
 * As such, only define these if the architecture-specific part of the
 * module didn't already.
 */

#ifndef ATOMIC_ARCH_SPECIFIC_LOAD
#define atomic_load(ptr, mo) __atomic_load_n(ptr, mo)
#endif

#ifndef ATOMIC_ARCH_SPECIFIC_STORE
#define atomic_store(ptr, val, mo) __atomic_store_n(ptr, val, mo)
#endif

/*
 * Common shortcuts.
 */

#define atomic_cas_acquire(ptr, oval, nval) \
    atomic_cas(ptr, oval, nval, ATOMIC_ACQUIRE)

#define atomic_cas_release(ptr, oval, nval) \
    atomic_cas(ptr, oval, nval, ATOMIC_RELEASE)

#define atomic_cas_acq_rel(ptr, oval, nval) \
    atomic_cas(ptr, oval, nval, ATOMIC_ACQ_REL)

#define atomic_swap_acquire(ptr, val)   atomic_swap(ptr, val, ATOMIC_ACQUIRE)
#define atomic_swap_release(ptr, val)   atomic_swap(ptr, val, ATOMIC_RELEASE)
#define atomic_swap_acq_rel(ptr, val)   atomic_swap(ptr, val, ATOMIC_ACQ_REL)

#define atomic_fetch_add_acq_rel(ptr, val) \
    atomic_fetch_add(ptr, val, ATOMIC_ACQ_REL)

#define atomic_fetch_sub_acq_rel(ptr, val) \
    atomic_fetch_sub(ptr, val, ATOMIC_ACQ_REL)

#define atomic_or_acq_rel(ptr, val)    atomic_or(ptr, val, ATOMIC_ACQ_REL)
#define atomic_and_acq_rel(ptr, val)   atomic_and(ptr, val, ATOMIC_ACQ_REL)

#endif /* _KERN_ATOMIC_H */
