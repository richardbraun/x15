/*
 * Copyright (c) 2017 Richard Braun.
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
 * This implementation is based on the paper "Algorithms for Scalable
 * Synchronization on Shared-Memory Multiprocessors" by John M. Mellor-Crummey
 * and Michael L. Scott, which describes MCS locks, among other algorithms.
 *
 * In order to avoid the need to allocate a qnode for every spin lock
 * currently held, and also to keep the size of locks to a single 32-bits
 * word, this module actually uses a variant of the MCS locks. The
 * differences are presented below.
 *
 * First, the lock owner is never part of the lock queue. This makes it
 * possible to use a qnode only during the lock operation, not after.
 * This means a single qnode per execution context is required even when
 * holding multiple spin locks simultaneously. In order to achieve that,
 * a spin lock not only refers to the last waiter, but also to the first,
 * which is the owner's qnode->next in the original algorithm.
 *
 * Next, instead of two pointers, the lock is a single word storing
 * compressed references to both the first and last waiters. Those
 * references are integers called QIDs, for qnode IDs. They can be
 * broken down into 3 parts :
 *  - the lock bit
 *  - the execution context
 *  - the target CPU ID
 *
 * The layout of a QID is carefully crafted to match the lock values
 * expected by the fast paths. Without contention, a QID value must
 * be SPINLOCK_UNLOCKED when a lock isn't held, and SPINLOCK_LOCKED
 * when it is. Besides, without contention, the reference to the first
 * waiter is logically NULL so that the whole lock value matches one
 * of SPINLOCK_UNLOCKED or SPINLOCK_LOCKED. This means that the values
 * of the execution context and the CPU ID must be 0 in the absence of
 * contention. In the presence of contention, the execution context and
 * CPU ID are used to uniquely identify a statically allocated qnode,
 * and fast paths operations fail. The lock operation must make sure
 * that the lock value is restored to SPINLOCK_LOCKED if there is no
 * more contention, an operation called downgrading.
 */

#include <stddef.h>

#include <kern/assert.h>
#include <kern/atomic.h>
#include <kern/error.h>
#include <kern/macros.h>
#include <kern/percpu.h>
#include <kern/spinlock.h>
#include <kern/spinlock_i.h>
#include <kern/spinlock_types.h>
#include <kern/thread.h>
#include <machine/cpu.h>
#include <machine/mb.h>

#define SPINLOCK_QID_LOCK_BIT       1

#define SPINLOCK_QID_CTX_BITS       2
#define SPINLOCK_QID_CTX_SHIFT      SPINLOCK_QID_LOCK_BIT
#define SPINLOCK_QID_CTX_MAX        (1 << SPINLOCK_QID_CTX_BITS)
#define SPINLOCK_QID_CTX_MASK       (SPINLOCK_QID_CTX_MAX - 1)

#define SPINLOCK_QID_CPU_BITS       13
#define SPINLOCK_QID_CPU_SHIFT      (SPINLOCK_QID_CTX_BITS \
                                     + SPINLOCK_QID_CTX_SHIFT)
#define SPINLOCK_QID_CPU_MAX        (1 << SPINLOCK_QID_CPU_BITS)
#define SPINLOCK_QID_CPU_MASK       (SPINLOCK_QID_CPU_MAX - 1)

#define SPINLOCK_QID_BITS           (SPINLOCK_QID_CPU_BITS          \
                                     + SPINLOCK_QID_CTX_BITS        \
                                     + SPINLOCK_QID_LOCK_BIT)
#define SPINLOCK_QID_MAX            (1 << SPINLOCK_QID_BITS)
#define SPINLOCK_QID_MASK           (SPINLOCK_QID_MAX - 1)

#define SPINLOCK_QID_MAX_BITS       16

#define SPINLOCK_QID_NULL           SPINLOCK_UNLOCKED
#define SPINLOCK_QID_LOCKED         SPINLOCK_LOCKED

#if SPINLOCK_QID_BITS > SPINLOCK_QID_MAX_BITS
#error "spinlock qid too large"
#endif

#if X15_MAX_CPUS > (1 << SPINLOCK_QID_CPU_BITS)
#error "maximum number of supported processors too large"
#endif

struct spinlock_qnode {
    unsigned int next_qid;
    bool locked;
};

#define SPINLOCK_CTX_INVALID    0
#define SPINLOCK_CTX_THREAD     1
#define SPINLOCK_CTX_INTR       2
#define SPINLOCK_CTX_NMI        3
#define SPINLOCK_NR_CTXS        4

#if SPINLOCK_CTX_INVALID != 0
#error "the invalid context value must be 0"
#endif

#if SPINLOCK_NR_CTXS > SPINLOCK_QID_CTX_MAX
#error "maximum number of contexts too large"
#endif

struct spinlock_cpu_data {
    struct spinlock_qnode qnodes[SPINLOCK_NR_CTXS - 1] __aligned(CPU_L1_SIZE);
};

static struct spinlock_cpu_data spinlock_cpu_data __percpu;

void
spinlock_init(struct spinlock *lock)
{
    lock->value = SPINLOCK_UNLOCKED;
}

static unsigned int
spinlock_qid2ctx(unsigned int qid)
{
    return (qid >> SPINLOCK_QID_CTX_SHIFT) & SPINLOCK_QID_CTX_MASK;
}

static unsigned int
spinlock_qid2cpu(unsigned int qid)
{
    return (qid >> SPINLOCK_QID_CPU_SHIFT) & SPINLOCK_QID_CPU_MASK;
}

static unsigned int
spinlock_build_qid(unsigned int cpu, unsigned int ctx)
{
    return (cpu << SPINLOCK_QID_CPU_SHIFT)
           | (ctx << SPINLOCK_QID_CTX_SHIFT)
           | SPINLOCK_QID_LOCK_BIT;
}

static void
spinlock_get_local_qnode(struct spinlock_qnode **qnodep, unsigned int *qidp)
{
    struct spinlock_cpu_data *cpu_data;
    unsigned int ctx;

    cpu_data = cpu_local_ptr(spinlock_cpu_data);

    /* TODO NMI support */
    ctx = thread_interrupted() ? SPINLOCK_CTX_INTR : SPINLOCK_CTX_THREAD;
    *qnodep = &cpu_data->qnodes[ctx - 1];
    *qidp = spinlock_build_qid(cpu_id(), ctx);
}

static struct spinlock_qnode *
spinlock_get_remote_qnode(unsigned int qid)
{
    struct spinlock_cpu_data *cpu_data;
    unsigned int ctx, cpu;

    ctx = spinlock_qid2ctx(qid);

    if (ctx == SPINLOCK_CTX_INVALID) {
        return NULL;
    }

    ctx--;
    assert(ctx < ARRAY_SIZE(cpu_data->qnodes));

    cpu = spinlock_qid2cpu(qid);
    cpu_data = percpu_ptr(spinlock_cpu_data, cpu);
    return &cpu_data->qnodes[ctx];
}

static void
spinlock_store_first_qid(struct spinlock *lock, unsigned int newqid)
{
    unsigned int oldval, newval, prev;

    assert(newqid < SPINLOCK_QID_MAX);

    newqid <<= SPINLOCK_QID_MAX_BITS;

    do {
        oldval = read_once(lock->value);
        newval = newqid | (oldval & SPINLOCK_QID_MASK);
        prev = atomic_cas_acquire(&lock->value, oldval, newval);
    } while (prev != oldval);
}

static unsigned int
spinlock_load_first_qid(const struct spinlock *lock)
{
    unsigned int value;

    value = read_once(lock->value);
    return (value >> SPINLOCK_QID_MAX_BITS) & SPINLOCK_QID_MASK;
}

static unsigned int
spinlock_swap_last_qid(struct spinlock *lock, unsigned int newqid)
{
    unsigned int oldval, newval, prev;

    assert(newqid < SPINLOCK_QID_MAX);

    do {
        oldval = read_once(lock->value);
        newval = (oldval & (SPINLOCK_QID_MASK << SPINLOCK_QID_MAX_BITS))
                 | newqid;
        prev = atomic_cas_acquire(&lock->value, oldval, newval);
    } while (prev != oldval);

    return prev & SPINLOCK_QID_MASK;
}

static unsigned int
spinlock_try_downgrade(struct spinlock *lock, unsigned int oldqid)
{
    unsigned int prev;

    prev = atomic_cas_acquire(&lock->value, oldqid, SPINLOCK_QID_LOCKED);

    assert((prev >> SPINLOCK_QID_MAX_BITS) == 0);
    assert(prev != SPINLOCK_QID_NULL);

    if (prev != oldqid) {
        return ERROR_BUSY;
    }

    return 0;
}

void
spinlock_lock_slow(struct spinlock *lock)
{
    struct spinlock_qnode *qnode, *prev_qnode;
    unsigned int qid, prev_qid, next_qid, ctx;
    bool locked;
    int error;

    spinlock_get_local_qnode(&qnode, &qid);
    qnode->next_qid = SPINLOCK_QID_NULL;

    prev_qid = spinlock_swap_last_qid(lock, qid);

    if (prev_qid != SPINLOCK_QID_NULL) {
        qnode->locked = true;
        ctx = spinlock_qid2ctx(prev_qid);

        if (ctx == SPINLOCK_CTX_INVALID) {
            spinlock_store_first_qid(lock, qid);
        } else {
            prev_qnode = spinlock_get_remote_qnode(prev_qid);
            write_once(prev_qnode->next_qid, qid);
        }

        for (;;) {
            locked = read_once(qnode->locked);
            mb_load();

            if (!locked) {
                break;
            }

            cpu_pause();
        }

        spinlock_store_first_qid(lock, SPINLOCK_QID_NULL);
    }

    error = spinlock_try_downgrade(lock, qid);

    if (!error) {
        return;
    }

    for (;;) {
        next_qid = read_once(qnode->next_qid);

        if (next_qid != SPINLOCK_QID_NULL) {
            break;
        }

        cpu_pause();
    }

    spinlock_store_first_qid(lock, next_qid);
}

void
spinlock_unlock_slow(struct spinlock *lock)
{
    struct spinlock_qnode *next_qnode;
    unsigned int next_qid;

    for (;;) {
        next_qid = spinlock_load_first_qid(lock);

        if (next_qid != SPINLOCK_QID_NULL) {
            break;
        }

        cpu_pause();
    }

    mb_store();
    next_qnode = spinlock_get_remote_qnode(next_qid);
    write_once(next_qnode->locked, false);
}
