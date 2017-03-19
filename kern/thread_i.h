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
 */

#ifndef _KERN_THREAD_I_H
#define _KERN_THREAD_I_H

#include <stdbool.h>

#include <kern/condition_types.h>
#include <kern/cpumap.h>
#include <kern/list_types.h>
#include <kern/macros.h>
#include <kern/mutex_types.h>
#include <kern/param.h>
#include <kern/turnstile_types.h>
#include <machine/atomic.h>
#include <machine/tcb.h>

/*
 * Forward declarations.
 */
struct sleepq;

struct thread_runq;
struct thread_fs_runq;

/*
 * Thread flags.
 */
#define THREAD_YIELD    0x1UL /* Must yield the processor ASAP */
#define THREAD_DETACHED 0x2UL /* Resources automatically released on exit */

/*
 * Thread states.
 *
 * Threads in the running state may not be on a run queue if they're being
 * awaken.
 */
#define THREAD_RUNNING  0
#define THREAD_SLEEPING 1
#define THREAD_DEAD     2

/*
 * Scheduling data for a real-time thread.
 */
struct thread_rt_data {
    struct list node;
    unsigned short time_slice;
};

/*
 * Scheduling data for a fair-scheduling thread.
 */
struct thread_fs_data {
    struct list group_node;
    struct list runq_node;
    struct thread_fs_runq *fs_runq;
    unsigned long round;
    unsigned short weight;
    unsigned short work;
};

/*
 * Maximum number of thread-specific data keys.
 */
#define THREAD_KEYS_MAX 4

/*
 * Thread structure.
 *
 * Threads don't have their own lock. Instead, the associated run queue
 * lock is used for synchronization. A number of members are thread-local
 * and require no synchronization. Others must be accessed with atomic
 * instructions.
 *
 * Locking keys :
 * (r) run queue
 * (t) turnstile_td
 * (T) task
 * (j) join_lock
 * (a) atomic
 * (-) thread-local
 * ( ) read-only
 */
struct thread {
    struct tcb tcb;         /* (r) */

    unsigned long nr_refs;  /* (a) */
    unsigned long flags;    /* (a) */

    /* Sleep/wake-up synchronization members */
    struct thread_runq *runq;   /* (r) */
    bool in_runq;               /* (r) */
    const void *wchan_addr;     /* (r) */
    const char *wchan_desc;     /* (r) */
    unsigned short state;       /* (r) */

    /* Sleep queue available for lending */
    struct sleepq *priv_sleepq; /* (-) */

    /* Turnstile available for lending */
    struct turnstile *priv_turnstile;   /* (-) */

    /*
     * When a thread wakes up after waiting for a condition variable,
     * it sets this variable so that other waiters are only awaken
     * after the associated mutex has actually been released.
     *
     * This member is thread-local.
     */
    struct condition *last_cond;        /* (-) */

    struct turnstile_td turnstile_td;   /* (t) */

    /* True if priority must be propagated when preemption is reenabled */
    bool propagate_priority;    /* (-) */

    /* Preemption counter, preemption is enabled if 0 */
    unsigned short preempt;     /* (-) */

    /* Pinning counter, migration is allowed if 0 */
    unsigned short pinned;      /* (-) */

    /* Interrupt level counter, in thread context if 0 */
    unsigned short intr;        /* (-) */

    /* Read-side critical section counter, not in any if 0 */
    unsigned short llsync_read; /* (-) */

    /* Processors on which this thread is allowed to run */
    struct cpumap cpumap;   /* (r) */

    struct thread_sched_data user_sched_data;   /* (r,t) */
    struct thread_sched_data real_sched_data;   /* (r,t) */

    /*
     * True if the real scheduling data are not the user scheduling data.
     *
     * Note that it doesn't provide any information about priority inheritance.
     * A thread may be part of a priority inheritance chain without its
     * priority being boosted.
     */
    bool boosted;   /* (r,t) */

    union {
        struct thread_rt_data rt_data;  /* (r) */
        struct thread_fs_data fs_data;  /* (r) */
    };

    /*
     * Thread-specific data should only be used by architecture-dependent code.
     * For machine-independent code, new member variables should be added.
     *
     * TODO move those to the TCB and remove.
     */
    void *tsd[THREAD_KEYS_MAX];

    /* Members related to termination */
    struct mutex join_lock;
    struct condition join_cond;     /* (j) */
    int exited;                     /* (j) */

    struct task *task;              /* (T) */
    struct list task_node;          /* (T) */
    void *stack;                    /* (-) */
    char name[THREAD_NAME_SIZE];    /* ( ) */

    /* TODO Move out of the structure and make temporary */
    void (*fn)(void *);
    void *arg;
} __aligned(CPU_L1_SIZE);

#define THREAD_ATTR_DETACHED 0x1

void thread_destroy(struct thread *thread);

/*
 * Flag access functions.
 */

static inline void
thread_set_flag(struct thread *thread, unsigned long flag)
{
    atomic_or_ulong(&thread->flags, flag);
}

static inline void
thread_clear_flag(struct thread *thread, unsigned long flag)
{
    atomic_and_ulong(&thread->flags, ~flag);
}

static inline int
thread_test_flag(struct thread *thread, unsigned long flag)
{
    barrier();
    return ((thread->flags & flag) != 0);
}

#endif /* _KERN_THREAD_I_H */
