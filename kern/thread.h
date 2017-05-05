/*
 * Copyright (c) 2012-2017 Richard Braun.
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
 * round-robin (SCHED_RR) policies, while the "fair-scheduling" policy (FS)
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

#include <stdbool.h>
#include <stddef.h>

#include <kern/assert.h>
#include <kern/atomic.h>
#include <kern/condition.h>
#include <kern/cpumap.h>
#include <kern/macros.h>
#include <kern/spinlock_types.h>
#include <kern/turnstile_types.h>
#include <machine/cpu.h>
#include <machine/tcb.h>

/*
 * Thread structure.
 */
struct thread;

/*
 * The global priority of a thread is meant to be compared against
 * another global priority to determine which thread has higher priority.
 */
struct thread_sched_data {
    unsigned char sched_policy;
    unsigned char sched_class;
    unsigned short priority;
    unsigned int global_priority;
};

/*
 * Thread name buffer size.
 */
#define THREAD_NAME_SIZE 32

#include <kern/thread_i.h>

#define THREAD_KERNEL_PREFIX PACKAGE "_"

/*
 * Scheduling policies.
 *
 * The idle policy is reserved for the per-CPU idle threads.
 */
#define THREAD_SCHED_POLICY_FIFO    0
#define THREAD_SCHED_POLICY_RR      1
#define THREAD_SCHED_POLICY_FS      2
#define THREAD_SCHED_POLICY_IDLE    3
#define THREAD_NR_SCHED_POLICIES    4

/*
 * Real-time priority properties.
 */
#define THREAD_SCHED_RT_PRIO_MIN        0
#define THREAD_SCHED_RT_PRIO_MAX        31

/*
 * Fair-scheduling priority properties.
 */
#define THREAD_SCHED_FS_PRIO_MIN        0
#define THREAD_SCHED_FS_PRIO_DEFAULT    20
#define THREAD_SCHED_FS_PRIO_MAX        39

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
 *  - policy is fair-scheduling
 *  - priority is fair-scheduling default
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
    attr->policy = THREAD_SCHED_POLICY_FS;
    attr->priority = THREAD_SCHED_FS_PRIO_DEFAULT;
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
 * wake-ups, i.e. a wake-up request sent by another thread cannot be missed
 * if that thread is holding the interlock.
 *
 * As a special exception, threads that use preemption as a synchronization
 * mechanism can ommit the interlock and pass a NULL pointer instead.
 * In any case, the preemption nesting level must strictly be one when calling
 * this function.
 *
 * The wait channel describes the reason why the thread is sleeping. The
 * address should refer to a relevant synchronization object, normally
 * containing the interlock, but not necessarily.
 *
 * Implies a memory barrier.
 */
void thread_sleep(struct spinlock *interlock, const void *wchan_addr,
                  const char *wchan_desc);

/*
 * Schedule a thread for execution on a processor.
 *
 * No action is performed if the target thread is already in the running state.
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
 * Set thread scheduling parameters.
 */
void thread_setscheduler(struct thread *thread, unsigned char policy,
                         unsigned short priority);

/*
 * Variant used for priority inheritance.
 *
 * The caller must hold the turnstile thread data lock and no turnstile
 * locks when calling this function.
 */
void thread_pi_setscheduler(struct thread *thread, unsigned char policy,
                            unsigned short priority);

static inline void
thread_ref(struct thread *thread)
{
    unsigned long nr_refs;

    nr_refs = atomic_fetch_add(&thread->nr_refs, 1, ATOMIC_RELAXED);
    assert(nr_refs != (unsigned long)-1);
}

static inline void
thread_unref(struct thread *thread)
{
    unsigned long nr_refs;

    nr_refs = atomic_fetch_sub_acq_rel(&thread->nr_refs, 1);
    assert(nr_refs != 0);

    if (nr_refs == 1) {
        thread_destroy(thread);
    }
}

static inline const void *
thread_wchan_addr(const struct thread *thread)
{
    return thread->wchan_addr;
}

static inline const char *
thread_wchan_desc(const struct thread *thread)
{
    return thread->wchan_desc;
}

/*
 * Return a character representation of the state of a thread.
 */
char thread_state_to_chr(const struct thread *thread);

static inline const struct thread_sched_data *
thread_get_user_sched_data(const struct thread *thread)
{
    return &thread->user_sched_data;
}

static inline const struct thread_sched_data *
thread_get_real_sched_data(const struct thread *thread)
{
    return &thread->real_sched_data;
}

/*
 * If the caller requires the scheduling data to be stable, it
 * must lock one of the following objects :
 *  - the containing run queue
 *  - the per-thread turnstile data (turnstile_td)
 *
 * Both are locked when scheduling data are updated.
 */

static inline unsigned char
thread_user_sched_policy(const struct thread *thread)
{
    return thread_get_user_sched_data(thread)->sched_policy;
}

static inline unsigned char
thread_user_sched_class(const struct thread *thread)
{
    return thread_get_user_sched_data(thread)->sched_class;
}

static inline unsigned short
thread_user_priority(const struct thread *thread)
{
    return thread_get_user_sched_data(thread)->priority;
}

static inline unsigned int
thread_user_global_priority(const struct thread *thread)
{
    return thread_get_user_sched_data(thread)->global_priority;
}

static inline unsigned char
thread_real_sched_policy(const struct thread *thread)
{
    return thread_get_real_sched_data(thread)->sched_policy;
}

static inline unsigned char
thread_real_sched_class(const struct thread *thread)
{
    return thread_get_real_sched_data(thread)->sched_class;
}

static inline unsigned short
thread_real_priority(const struct thread *thread)
{
    return thread_get_real_sched_data(thread)->priority;
}

static inline unsigned int
thread_real_global_priority(const struct thread *thread)
{
    return thread_get_real_sched_data(thread)->global_priority;
}

/*
 * Return a string representation of the scheduling class of a thread.
 */
const char * thread_sched_class_to_str(unsigned char sched_class);

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

    if (likely(!thread_test_flag(thread_self(), THREAD_YIELD))) {
        return;
    }

    thread_yield();
}

/*
 * Sleep queue lending functions.
 */

static inline struct sleepq *
thread_sleepq_lend(void)
{
    struct sleepq *sleepq;

    sleepq = thread_self()->priv_sleepq;
    assert(sleepq != NULL);
    thread_self()->priv_sleepq = NULL;
    return sleepq;
}

static inline void
thread_sleepq_return(struct sleepq *sleepq)
{
    assert(sleepq != NULL);
    assert(thread_self()->priv_sleepq == NULL);
    thread_self()->priv_sleepq = sleepq;
}

/*
 * Condition variable related functions.
 */

static inline void
thread_set_last_cond(struct condition *last_cond)
{
    struct thread *thread;

    thread = thread_self();
    assert(thread->last_cond == NULL);
    thread->last_cond = last_cond;
}

static inline struct condition *
thread_pull_last_cond(void)
{
    struct condition *last_cond;
    struct thread *thread;

    thread = thread_self();
    last_cond = thread->last_cond;

    if (last_cond != NULL) {
        thread->last_cond = NULL;
    }

    return last_cond;
}

static inline void
thread_wakeup_last_cond(void)
{
    struct condition *last_cond;

    last_cond = thread_pull_last_cond();

    if (last_cond != NULL) {
        condition_wakeup(last_cond);
    }
}

/*
 * Turnstile lending functions.
 */

static inline struct turnstile *
thread_turnstile_lend(void)
{
    struct turnstile *turnstile;

    turnstile = thread_self()->priv_turnstile;
    assert(turnstile != NULL);
    thread_self()->priv_turnstile = NULL;
    return turnstile;
}

static inline void
thread_turnstile_return(struct turnstile *turnstile)
{
    assert(turnstile != NULL);
    assert(thread_self()->priv_turnstile == NULL);
    thread_self()->priv_turnstile = turnstile;
}

static inline struct turnstile_td *
thread_turnstile_td(struct thread *thread)
{
    return &thread->turnstile_td;
}

/*
 * Priority propagation functions.
 */

static inline bool
thread_priority_propagation_needed(void)
{
    return thread_self()->propagate_priority;
}

static inline void
thread_set_priority_propagation_needed(void)
{
    thread_self()->propagate_priority = true;
}

void thread_propagate_priority(void);

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

    if (thread_preempt_enabled() && thread_priority_propagation_needed()) {
        thread_propagate_priority();
    }
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
 * Interrupt level control functions.
 *
 * Functions that change the interrupt level are implicit compiler barriers.
 */

static inline bool
thread_interrupted(void)
{
    return (thread_self()->intr != 0);
}

static inline void
thread_intr_enter(void)
{
    struct thread *thread;

    thread = thread_self();

    if (thread->intr == 0) {
        thread_preempt_disable();
    }

    thread->intr++;
    assert(thread->intr != 0);
    barrier();
}

static inline void
thread_intr_leave(void)
{
    struct thread *thread;

    barrier();
    thread = thread_self();
    assert(thread->intr != 0);
    thread->intr--;

    if (thread->intr == 0) {
        thread_preempt_enable_no_resched();
    }
}

static inline void
thread_assert_interrupted(void)
{
    assert(thread_interrupted());
    assert(!cpu_intr_enabled());
    assert(!thread_preempt_enabled());
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
    barrier();
}

static inline void
thread_llsync_read_dec(void)
{
    struct thread *thread;

    barrier();
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
