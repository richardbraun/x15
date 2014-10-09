/*
 * Copyright (c) 2012-2014 Richard Braun.
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
 * The thread module aims at providing an interface suitable to implement
 * POSIX scheduling policies. As such, it provides scheduling classes and
 * policies that closely match the standard ones. The "real-time" policies
 * (FIFO and RR) directly map the first-in first-out (SCHED_FIFO) and
 * round-robin (SCHED_RR) policies, while the "time-sharing" policy (TS,
 * named that way because, unlike real-time threads, time sharing is enforced)
 * can be used for the normal SCHED_OTHER policy. The idle policy is reserved
 * for idling kernel threads.
 *
 * By convention, the name of a kernel thread is built by concatenating the
 * kernel name and the name of the start function, separated with an underscore.
 * Threads that are bound to a processor also include the "/cpu_id" suffix.
 * For example, "x15_thread_balance/1" is the name of the inter-processor
 * balancer thread of the second processor.
 */

#ifndef _KERN_THREAD_H
#define _KERN_THREAD_H

#include <kern/assert.h>
#include <kern/cpumap.h>
#include <kern/list.h>
#include <kern/macros.h>
#include <kern/param.h>
#include <kern/types.h>
#include <machine/atomic.h>
#include <machine/cpu.h>
#include <machine/tcb.h>

/*
 * Forward declarations.
 */
struct spinlock;
struct task;
struct thread_runq;
struct thread_ts_runq;

/*
 * Thread name buffer size.
 */
#define THREAD_NAME_SIZE 32

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
#define THREAD_SCHED_RT_PRIO_MAX        63

/*
 * Scheduling data for a real-time thread.
 */
struct thread_rt_data {
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

/*
 * Scheduling data for a time-sharing thread.
 */
struct thread_ts_data {
    struct list group_node;
    struct list runq_node;
    struct thread_ts_runq *ts_runq;
    unsigned long round;
    unsigned short priority;
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
 * Thread members are normally protected by the lock of the run queue they're
 * associated with. Thread-local members are accessed without synchronization.
 */
struct thread {
    struct tcb tcb;

    /* Flags must be changed atomically */
    unsigned long flags;

    /* Sleep/wakeup synchronization members */
    struct thread_runq *runq;
    unsigned short state;

    /* Thread-local members */
    unsigned short preempt;
    unsigned short pinned;
    unsigned short llsync_read;

    /* Common scheduling properties */
    unsigned char sched_policy;
    unsigned char sched_class;

    /* Processors on which this thread is allowed to run */
    struct cpumap cpumap;

    /* Scheduling class specific data */
    union {
        struct thread_rt_data rt_data;
        struct thread_ts_data ts_data;
    };

    /* Thread-specific data */
    void *tsd[THREAD_KEYS_MAX];

    /* Members related to termination */
    struct mutex join_lock;
    struct condition join_cond;
    int exited;

    /* Read-only members */
    struct task *task;
    struct list task_node;
    void *stack;
    char name[THREAD_NAME_SIZE];
    void (*fn)(void *);
    void *arg;
} __aligned(CPU_L1_SIZE);

#define THREAD_ATTR_DETACHED 0x1

/*
 * Thread creation attributes.
 */
struct thread_attr {
    const char *name;
    unsigned long flags;
    struct cpumap *cpumap;
    struct task *task;
    unsigned char policy;
    unsigned short priority;
};

/*
 * Initialize thread creation attributes with default values.
 *
 * It is guaranteed that these default values include :
 *  - thread is joinable
 *  - no processor affinity
 *  - task is inherited from parent thread
 *  - policy is time-sharing
 *  - priority is time-sharing default
 *
 * If the policy is changed, the priority, if applicable, must be updated
 * as well.
 */
static inline void
thread_attr_init(struct thread_attr *attr, const char *name)
{
    attr->name = name;
    attr->flags = 0;
    attr->cpumap = NULL;
    attr->task = NULL;
    attr->policy = THREAD_SCHED_POLICY_TS;
    attr->priority = THREAD_SCHED_TS_PRIO_DEFAULT;
}

static inline void
thread_attr_set_detached(struct thread_attr *attr)
{
    attr->flags |= THREAD_ATTR_DETACHED;
}

static inline void
thread_attr_set_cpumap(struct thread_attr *attr, struct cpumap *cpumap)
{
    attr->cpumap = cpumap;
}

static inline void
thread_attr_set_task(struct thread_attr *attr, struct task *task)
{
    attr->task = task;
}

static inline void
thread_attr_set_policy(struct thread_attr *attr, unsigned char policy)
{
    attr->policy = policy;
}

static inline void
thread_attr_set_priority(struct thread_attr *attr, unsigned short priority)
{
    attr->priority = priority;
}

/*
 * Early initialization of the thread module.
 *
 * These function make it possible to use migration and preemption control
 * operations (and in turn, spin locks) during bootstrap.
 */
void thread_bootstrap(void);
void thread_ap_bootstrap(void);

/*
 * Initialize the thread module.
 */
void thread_setup(void);

/*
 * Create a thread.
 *
 * Creation attributes must be passed, but some of them may be NULL, in which
 * case the value is inherited from the caller. The name attribute must not be
 * NULL.
 */
int thread_create(struct thread **threadp, const struct thread_attr *attr,
                  void (*fn)(void *), void *arg);

/*
 * Terminate the calling thread.
 */
void __noreturn thread_exit(void);

/*
 * Wait for the given thread to terminate and release its resources.
 */
void thread_join(struct thread *thread);

/*
 * Make the current thread sleep while waiting for an event.
 *
 * The interlock is used to synchronize the thread state with respect to
 * wakeups, i.e. a wakeup request sent by another thread will not be missed
 * if that thread is holding the interlock.
 * As a special exception, threads that use preemption as a synchronization
 * mechanism can ommit the interlock and pass a NULL pointer instead.
 * In any case, the preemption nesting level must strictly be one when calling
 * this function.
 *
 * This is a low level thread control primitive that should only be called by
 * higher thread synchronization functions.
 *
 * Implies a memory barrier.
 */
void thread_sleep(struct spinlock *interlock);

/*
 * Schedule a thread for execution on a processor.
 *
 * No action is performed if the target thread is already in the running state.
 *
 * This is a low level thread control primitive that should only be called by
 * higher thread synchronization functions.
 */
void thread_wakeup(struct thread *thread);

/*
 * Start running threads on the local processor.
 *
 * Interrupts must be disabled when calling this function.
 */
void __noreturn thread_run_scheduler(void);

/*
 * Make the calling thread release the processor.
 *
 * This call does nothing if preemption is disabled, or the scheduler
 * determines the caller should continue to run (e.g. it's currently the only
 * runnable thread).
 */
void thread_yield(void);

/*
 * Report a scheduling interrupt from a remote processor.
 */
void thread_schedule_intr(void);

/*
 * Report a periodic timer interrupt on the thread currently running on
 * the local processor.
 */
void thread_tick_intr(void);

/*
 * Return a character representation of the state of a thread.
 */
char thread_state_to_chr(const struct thread *thread);

/*
 * Return a string representation of the scheduling class of a thread.
 */
const char * thread_schedclass_to_str(const struct thread *thread);

/*
 * Return the priority of a thread.
 *
 * If the scheduling class doesn't use a priority, return 0.
 */
unsigned int thread_schedprio(const struct thread *thread);

static inline struct thread *
thread_from_tcb(struct tcb *tcb)
{
    return structof(tcb, struct thread, tcb);
}

static inline struct thread *
thread_self(void)
{
    return thread_from_tcb(tcb_current());
}

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

/*
 * Main scheduler invocation call.
 *
 * Called on return from interrupt or when reenabling preemption.
 *
 * Implies a compiler barrier.
 */
static inline void
thread_schedule(void)
{
    barrier();

    if (likely(!thread_test_flag(thread_self(), THREAD_YIELD)))
        return;

    thread_yield();
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
    thread_schedule();
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

/*
 * Lockless synchronization read-side critical section nesting counter
 * control functions.
 */

static inline int
thread_llsync_in_read_cs(void)
{
    struct thread *thread;

    thread = thread_self();
    return (thread->llsync_read != 0);
}

static inline void
thread_llsync_read_inc(void)
{
    struct thread *thread;

    thread = thread_self();
    thread->llsync_read++;
    assert(thread->llsync_read != 0);
}

static inline void
thread_llsync_read_dec(void)
{
    struct thread *thread;

    thread = thread_self();
    assert(thread->llsync_read != 0);
    thread->llsync_read--;
}

/*
 * Type for thread-specific data destructor.
 */
typedef void (*thread_dtor_fn_t)(void *);

/*
 * Allocate a TSD key.
 *
 * If not NULL, the destructor is called on thread destruction on the pointer
 * associated with the allocated key.
 */
void thread_key_create(unsigned int *keyp, thread_dtor_fn_t dtor);

/*
 * Set the pointer associated with a key for the given thread.
 */
static inline void
thread_tsd_set(struct thread *thread, unsigned int key, void *ptr)
{
    thread->tsd[key] = ptr;
}

/*
 * Return the pointer associated with a key for the given thread.
 */
static inline void *
thread_tsd_get(struct thread *thread, unsigned int key)
{
    return thread->tsd[key];
}

/*
 * Set the pointer associated with a key for the calling thread.
 */
static inline void
thread_set_specific(unsigned int key, void *ptr)
{
    thread_tsd_set(thread_self(), key, ptr);
}

/*
 * Return the pointer associated with a key for the calling thread.
 */
static inline void *
thread_get_specific(unsigned int key)
{
    return thread_tsd_get(thread_self(), key);
}

#endif /* _KERN_THREAD_H */
