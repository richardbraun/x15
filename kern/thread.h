/*
 * Copyright (c) 2012, 2013 Richard Braun.
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

#ifndef _KERN_THREAD_H
#define _KERN_THREAD_H

#include <kern/assert.h>
#include <kern/list.h>
#include <kern/macros.h>
#include <kern/param.h>
#include <machine/cpu.h>
#include <machine/tcb.h>

/*
 * Forward declaration.
 */
struct task;

/*
 * Thread name buffer size.
 */
#define THREAD_NAME_SIZE 32

/*
 * Thread flags.
 */
#define THREAD_RESCHEDULE   0x1 /* Thread marked for reschedule */

/*
 * Thread states.
 */
#define THREAD_RUNNING  0
#define THREAD_SLEEPING 1

/*
 * Scheduling policies.
 *
 * The idle policy is reserved for the per-CPU idle threads.
 */
#define THREAD_SCHED_POLICY_FIFO    0
#define THREAD_SCHED_POLICY_RR      1
#define THREAD_SCHED_POLICY_TS      2
#define THREAD_SCHED_POLICY_IDLE    3
#define THREAD_NR_SCHED_POLICIES    4

/*
 * Scheduling classes.
 *
 * Classes are sorted by order of priority (lower indexes first). The same
 * class can apply to several policies.
 *
 * The idle class is reserved for the per-CPU idle threads.
 */
#define THREAD_SCHED_CLASS_RT   0
#define THREAD_SCHED_CLASS_TS   1
#define THREAD_SCHED_CLASS_IDLE 2
#define THREAD_NR_SCHED_CLASSES 3

/*
 * Real-time priority properties.
 */
#define THREAD_SCHED_RT_PRIO_MIN        0
#define THREAD_SCHED_RT_PRIO_MAX        31

/*
 * Scheduling context of a real-time thread.
 */
struct thread_rt_ctx {
    struct list node;
    unsigned short priority;
    unsigned short time_slice;
};

/*
 * Time-sharing priority properties.
 */
#define THREAD_SCHED_TS_PRIO_MIN        0
#define THREAD_SCHED_TS_PRIO_DEFAULT    20
#define THREAD_SCHED_TS_PRIO_MAX        39

struct thread_ts_runq;

/*
 * Scheduling context of a time-sharing thread.
 */
struct thread_ts_ctx {
    struct list node;
    struct thread_ts_runq *ts_runq;
    unsigned short weight;
    unsigned short work;
};

/*
 * Thread structure.
 */
struct thread {
    struct tcb tcb;
    short state;
    short flags;
    unsigned short pinned;
    unsigned short preempt;
    unsigned int cpu;
    unsigned long on_rq;

    /* Common scheduling properties */
    unsigned char sched_policy;
    unsigned char sched_class;

    /* Scheduling class specific contexts */
    union {
        struct thread_rt_ctx rt_ctx;
        struct thread_ts_ctx ts_ctx;
    };

    struct task *task;
    struct list task_node;
    void *stack;
    char name[THREAD_NAME_SIZE];
    void (*fn)(void *);
    void *arg;
} __aligned(CPU_L1_SIZE);

/*
 * Thread creation attributes.
 */
struct thread_attr {
    struct task *task;
    const char *name;
    unsigned char sched_policy;
    unsigned short priority;
};

/*
 * Early initialization of the thread module.
 *
 * This function makes it possible to use migration and preemption control
 * operations while the system is initializing itself.
 */
void thread_bootstrap(void);

/*
 * Early initialization of the TCB on APs.
 */
void thread_ap_bootstrap(void);

/*
 * Initialize the thread module.
 */
void thread_setup(void);

/*
 * Create a thread.
 *
 * If the given attributes are NULL, default attributes are used. If the task
 * is NULL, the caller task is selected. If the name is NULL, the task name is
 * used instead. The default attributes also select the caller task and task
 * name.
 */
int thread_create(struct thread **threadp, const struct thread_attr *attr,
                  void (*fn)(void *), void *arg);

/*
 * Make the scheduler remove the calling thread from its run queue.
 *
 * This is a low level thread control primitive that should only be called by
 * higher thread synchronization functions.
 */
void thread_sleep(void);

/*
 * Schedule the target thread for execution on a processor.
 *
 * No action is performed if the target thread is already on a run queue.
 *
 * This is a low level thread control primitive that should only be called by
 * higher thread synchronization functions.
 */
void thread_wakeup(struct thread *thread);

/*
 * Start running threads on the local processor.
 *
 * Interrupts must be enabled when calling this function.
 */
void __noreturn thread_run(void);

/*
 * Invoke the scheduler.
 */
void thread_schedule(void);

/*
 * Invoke the scheduler if the calling thread is marked for reschedule.
 */
void thread_reschedule(void);

/*
 * Report a periodic timer interrupt on the thread currently running on
 * the local processor.
 *
 * Called from interrupt context.
 */
void thread_tick(void);

static inline struct thread *
thread_self(void)
{
    return structof(tcb_current(), struct thread, tcb);
}

/*
 * Migration control functions.
 *
 * Functions that change the migration state are implicit compiler barriers.
 */

static inline int
thread_pinned(void)
{
    return (thread_self()->pinned != 0);
}

static inline void
thread_pin(void)
{
    struct thread *thread;

    thread = thread_self();
    thread->pinned++;
    assert(thread->pinned != 0);
    barrier();
}

static inline void
thread_unpin(void)
{
    struct thread *thread;

    barrier();
    thread = thread_self();
    assert(thread->pinned != 0);
    thread->pinned--;
}

/*
 * Preemption control functions.
 *
 * Functions that change the preemption state are implicit compiler barriers.
 */

static inline int
thread_preempt_enabled(void)
{
    return (thread_self()->preempt == 0);
}

static inline void
thread_preempt_enable_no_resched(void)
{
    struct thread *thread;

    barrier();
    thread = thread_self();
    assert(thread->preempt != 0);
    thread->preempt--;
}

static inline void
thread_preempt_enable(void)
{
    thread_preempt_enable_no_resched();
    thread_reschedule();
}

static inline void
thread_preempt_disable(void)
{
    struct thread *thread;

    thread = thread_self();
    thread->preempt++;
    assert(thread->preempt != 0);
    barrier();
}

#endif /* _KERN_THREAD_H */
