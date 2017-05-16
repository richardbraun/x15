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
 * The scheduling algorithm implemented by this module, named Distributed
 * Group Ratio Round-Robin (DGR3), is based on the following papers :
 *  - "Group Ratio Round-Robin: O(1) Proportional Share Scheduling for
 *    Uniprocessor and Multiprocessor Systems" by Bogdan Caprita, Wong Chun
 *    Chan, Jason Nieh, Clifford Stein and Haoqiang Zheng.
 *  - "Efficient and Scalable Multiprocessor Fair Scheduling Using Distributed
 *    Weighted Round-Robin" by Tong li, Dan Baumberger and Scott Hahn.
 *
 * Note that the Group Ratio Round-Robin (GR3) paper offers a multiprocessor
 * extension, but based on a single global queue, which strongly limits its
 * scalability on systems with many processors. That extension isn't used in
 * this implementation.
 *
 * The basic idea is to use GR3 for processor-local scheduling, and Distributed
 * Weighted Round-Robin (DWRR) for inter-processor load balancing. These
 * algorithms were chosen for several reasons. To begin with, they provide
 * fair scheduling, a very desirable property for a modern scheduler. Next,
 * being based on round-robin, their algorithmic complexity is very low (GR3
 * has O(1) scheduling complexity, and O(g) complexity on thread addition
 * or removal, g being the number of groups, with one group per priority, a
 * low number in practice). Finally, they're very simple to implement, making
 * them easy to adjust and maintain.
 *
 * Both algorithms are actually slightly modified for efficiency. First, this
 * version of GR3 is simplified by mapping exactly one group to one priority,
 * and in turn, one weight. This is possible because priorities are intended
 * to match Unix nice values, and systems commonly provide a constant, small
 * set of nice values. This removes the need for accounting deficit. Next,
 * round tracking is used to improve the handling of dynamic events : work
 * scaling is performed only on thread addition, and not when a thread that
 * was removed is added again during the same round. In addition, since GR3
 * is itself a round-robin algorithm, it already provides the feature required
 * from local scheduling by DWRR, namely round slicing. Consequently, DWRR
 * doesn't sit "on top" of GR3, but is actually merged with it. The result is
 * an algorithm that shares the same data for both local scheduling and load
 * balancing.
 *
 * A few terms are used by both papers with slightly different meanings. Here
 * are the definitions used in this implementation :
 *  - The time unit is the system timer period (1 / HZ)
 *  - Work is the amount of execution time units consumed
 *  - Weight is the amount of execution time units allocated
 *  - A round is the shortest period during which all threads in a run queue
 *    consume their allocated time (i.e. their work reaches their weight)
 *
 * TODO Sub-tick accounting.
 *
 * TODO Setting affinity after thread creation.
 *
 * TODO Take into account the underlying CPU topology (and adjust load
 * balancing to access the global highest round less frequently on large
 * processor groups, perhaps by applying the load balancing algorithm in a
 * bottom-up fashion with one highest round per processor group).
 *
 * TODO For now, interactivity can not be experimented. The current strategy
 * is to always add threads in front of their group queue and track rounds
 * so that they don't get more time than they should. A direct consequence
 * is that continually spawning threads at short intervals is likely to cause
 * starvation. This could be fixed by adding newly created threads at the back
 * of their group queue. For now, don't overengineer, and wait until all this
 * can actually be tested.
 *
 * TODO Review weight computation (it may be more appropriate to determine
 * weights in a smoother way than a raw scaling).
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <kern/assert.h>
#include <kern/atomic.h>
#include <kern/condition.h>
#include <kern/cpumap.h>
#include <kern/error.h>
#include <kern/init.h>
#include <kern/kmem.h>
#include <kern/list.h>
#include <kern/llsync.h>
#include <kern/macros.h>
#include <kern/mutex.h>
#include <kern/panic.h>
#include <kern/param.h>
#include <kern/percpu.h>
#include <kern/sleepq.h>
#include <kern/spinlock.h>
#include <kern/sref.h>
#include <kern/syscnt.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/turnstile.h>
#include <kern/work.h>
#include <machine/cpu.h>
#include <machine/pmap.h>
#include <machine/tcb.h>
#include <vm/vm_map.h>

/*
 * Preemption level of a suspended thread.
 *
 * The expected interrupt, preemption and run queue lock state when
 * dispatching a thread is :
 *  - interrupts disabled
 *  - preemption disabled
 *  - run queue locked
 *
 * Locking the run queue increases the preemption counter once more,
 * making its value 2.
 */
#define THREAD_SUSPEND_PREEMPT_LEVEL 2

/*
 * Scheduling classes.
 *
 * Classes are sorted by order of priority (lower indexes first). The same
 * class can apply to several policies.
 *
 * The idle class is reserved for the per-CPU idle threads.
 */
#define THREAD_SCHED_CLASS_RT   0
#define THREAD_SCHED_CLASS_FS   1
#define THREAD_SCHED_CLASS_IDLE 2
#define THREAD_NR_SCHED_CLASSES 3

/*
 * Global priority bases for each scheduling class.
 *
 * Global priorities are only used to determine which of two threads
 * has the higher priority, and should only matter for priority
 * inheritance.
 *
 * In the current configuration, all fair-scheduling threads have the
 * same global priority.
 */
#define THREAD_SCHED_GLOBAL_PRIO_RT     2
#define THREAD_SCHED_GLOBAL_PRIO_FS     1
#define THREAD_SCHED_GLOBAL_PRIO_IDLE   0

/*
 * Default time slice for real-time round-robin scheduling.
 */
#define THREAD_DEFAULT_RR_TIME_SLICE (HZ / 10)

/*
 * Maximum number of threads which can be pulled from a remote run queue
 * while interrupts are disabled.
 */
#define THREAD_MAX_MIGRATIONS 16

/*
 * Delay (in ticks) between two balance attempts when a run queue is idle.
 */
#define THREAD_IDLE_BALANCE_TICKS (HZ / 2)

/*
 * Run queue properties for real-time threads.
 */
struct thread_rt_runq {
    unsigned int bitmap;
    struct list threads[THREAD_SCHED_RT_PRIO_MAX + 1];
};

/*
 * Initial value of the highest round.
 *
 * Set to a high value to make sure overflows are correctly handled.
 */
#define THREAD_FS_INITIAL_ROUND ((unsigned long)-10)

/*
 * Round slice base unit for fair-scheduling threads.
 */
#define THREAD_FS_ROUND_SLICE_BASE (HZ / 10)

/*
 * Group of threads sharing the same weight.
 */
struct thread_fs_group {
    struct list node;
    struct list threads;
    unsigned int weight;
    unsigned int work;
};

/*
 * Run queue properties for fair-scheduling threads.
 *
 * The current group pointer has a valid address only when the run queue isn't
 * empty.
 */
struct thread_fs_runq {
    struct thread_fs_group group_array[THREAD_SCHED_FS_PRIO_MAX + 1];
    struct list groups;
    struct list threads;
    struct thread_fs_group *current;
    unsigned int nr_threads;
    unsigned int weight;
    unsigned int work;
};

/*
 * Per processor run queue.
 *
 * Locking multiple run queues is done in the ascending order of their CPU
 * identifier. Interrupts must be disabled whenever locking a run queue, even
 * a remote one, otherwise an interrupt (which invokes the scheduler on its
 * return path) may violate the locking order.
 */
struct thread_runq {
    struct spinlock lock;
    unsigned int cpu;
    unsigned int nr_threads;
    struct thread *current;

    /* Real-time related members */
    struct thread_rt_runq rt_runq;

    /*
     * Fair-scheduling related members.
     *
     * The current round is set when the active run queue becomes non-empty.
     * It's not reset when both run queues become empty. As a result, the
     * current round has a meaningful value only when at least one thread is
     * present, i.e. the global weight isn't zero.
     */
    unsigned long fs_round;
    unsigned int fs_weight;
    struct thread_fs_runq fs_runqs[2];
    struct thread_fs_runq *fs_runq_active;
    struct thread_fs_runq *fs_runq_expired;

    struct thread *balancer;
    struct thread *idler;

    /* Ticks before the next balancing attempt when a run queue is idle */
    unsigned int idle_balance_ticks;

    struct syscnt sc_schedule_intrs;
    struct syscnt sc_tick_intrs;
    struct syscnt sc_boosts;
} __aligned(CPU_L1_SIZE);

/*
 * Operations of a scheduling class.
 */
struct thread_sched_ops {
    struct thread_runq * (*select_runq)(struct thread *thread);
    void (*add)(struct thread_runq *runq, struct thread *thread);
    void (*remove)(struct thread_runq *runq, struct thread *thread);
    void (*put_prev)(struct thread_runq *runq, struct thread *thread);
    struct thread * (*get_next)(struct thread_runq *runq);
    void (*reset_priority)(struct thread *thread, unsigned short priority);
    void (*update_priority)(struct thread *thread, unsigned short priority);
    unsigned int (*get_global_priority)(unsigned short priority);
    void (*set_next)(struct thread_runq *runq, struct thread *thread);
    void (*tick)(struct thread_runq *runq, struct thread *thread);
};

static struct thread_runq thread_runq __percpu;

/*
 * Statically allocated fake threads that provide thread context to processors
 * during bootstrap.
 */
static struct thread thread_booters[X15_MAX_CPUS] __initdata;

static struct kmem_cache thread_cache;

#ifndef X15_THREAD_STACK_GUARD
static struct kmem_cache thread_stack_cache;
#endif /* X15_THREAD_STACK_GUARD */

static const unsigned char thread_policy_table[THREAD_NR_SCHED_POLICIES] = {
    [THREAD_SCHED_POLICY_FIFO] = THREAD_SCHED_CLASS_RT,
    [THREAD_SCHED_POLICY_RR] = THREAD_SCHED_CLASS_RT,
    [THREAD_SCHED_POLICY_FS] = THREAD_SCHED_CLASS_FS,
    [THREAD_SCHED_POLICY_IDLE] = THREAD_SCHED_CLASS_IDLE,
};

static const struct thread_sched_ops thread_sched_ops[THREAD_NR_SCHED_CLASSES];

/*
 * Map of run queues for which a processor is running.
 */
static struct cpumap thread_active_runqs;

/*
 * Map of idle run queues.
 *
 * Access to this map isn't synchronized. It is merely used as a fast hint
 * to find run queues that are likely to be idle.
 */
static struct cpumap thread_idle_runqs;

/*
 * System-wide value of the current highest round.
 *
 * This global variable is accessed without any synchronization. Its value
 * being slightly inaccurate doesn't harm the fairness properties of the
 * scheduling and load balancing algorithms.
 *
 * There can be moderate bouncing on this word so give it its own cache line.
 */
static struct {
    volatile unsigned long value __aligned(CPU_L1_SIZE);
} thread_fs_highest_round_struct;

#define thread_fs_highest_round (thread_fs_highest_round_struct.value)

/*
 * Number of TSD keys actually allocated.
 */
static unsigned int thread_nr_keys __read_mostly;

/*
 * Destructors installed for each key.
 */
static thread_dtor_fn_t thread_dtors[THREAD_KEYS_MAX] __read_mostly;

/*
 * List of threads pending for destruction by the reaper.
 */
static struct mutex thread_reap_lock;
static struct condition thread_reap_cond;
static struct list thread_reap_list;

struct thread_zombie {
    struct list node;
    struct thread *thread;
};

static unsigned char
thread_policy_to_class(unsigned char policy)
{
    assert(policy < ARRAY_SIZE(thread_policy_table));
    return thread_policy_table[policy];
}

static void
thread_set_wchan(struct thread *thread, const void *wchan_addr,
                 const char *wchan_desc)
{
    assert((wchan_addr != NULL) && (wchan_desc != NULL));

    thread->wchan_addr = wchan_addr;
    thread->wchan_desc = wchan_desc;
}

static void
thread_clear_wchan(struct thread *thread)
{
    thread->wchan_addr = NULL;
    thread->wchan_desc = NULL;
}

static const struct thread_sched_ops *
thread_get_sched_ops(unsigned char sched_class)
{
    assert(sched_class < ARRAY_SIZE(thread_sched_ops));
    return &thread_sched_ops[sched_class];
}

static const struct thread_sched_ops *
thread_get_user_sched_ops(const struct thread *thread)
{
    return thread_get_sched_ops(thread_user_sched_class(thread));
}

static const struct thread_sched_ops *
thread_get_real_sched_ops(const struct thread *thread)
{
    return thread_get_sched_ops(thread_real_sched_class(thread));
}

static void __init
thread_runq_init_rt(struct thread_runq *runq)
{
    struct thread_rt_runq *rt_runq;
    size_t i;

    rt_runq = &runq->rt_runq;
    rt_runq->bitmap = 0;

    for (i = 0; i < ARRAY_SIZE(rt_runq->threads); i++) {
        list_init(&rt_runq->threads[i]);
    }
}

static void __init
thread_fs_group_init(struct thread_fs_group *group)
{
    list_init(&group->threads);
    group->weight = 0;
    group->work = 0;
}

static void __init
thread_fs_runq_init(struct thread_fs_runq *fs_runq)
{
    size_t i;

    for (i = 0; i < ARRAY_SIZE(fs_runq->group_array); i++) {
        thread_fs_group_init(&fs_runq->group_array[i]);
    }

    list_init(&fs_runq->groups);
    list_init(&fs_runq->threads);
    fs_runq->nr_threads = 0;
    fs_runq->weight = 0;
    fs_runq->work = 0;
}

static void __init
thread_runq_init_fs(struct thread_runq *runq)
{
    runq->fs_weight = 0;
    runq->fs_runq_active = &runq->fs_runqs[0];
    runq->fs_runq_expired = &runq->fs_runqs[1];
    thread_fs_runq_init(runq->fs_runq_active);
    thread_fs_runq_init(runq->fs_runq_expired);
}

static void __init
thread_runq_init(struct thread_runq *runq, unsigned int cpu,
                 struct thread *booter)
{
    char name[SYSCNT_NAME_SIZE];

    spinlock_init(&runq->lock);
    runq->cpu = cpu;
    runq->nr_threads = 0;
    runq->current = booter;
    thread_runq_init_rt(runq);
    thread_runq_init_fs(runq);
    runq->balancer = NULL;
    runq->idler = NULL;
    runq->idle_balance_ticks = (unsigned int)-1;
    snprintf(name, sizeof(name), "thread_schedule_intrs/%u", cpu);
    syscnt_register(&runq->sc_schedule_intrs, name);
    snprintf(name, sizeof(name), "thread_tick_intrs/%u", cpu);
    syscnt_register(&runq->sc_tick_intrs, name);
    snprintf(name, sizeof(name), "thread_boosts/%u", cpu);
    syscnt_register(&runq->sc_boosts, name);
}

static inline struct thread_runq *
thread_runq_local(void)
{
    assert(!thread_preempt_enabled() || thread_pinned());
    return cpu_local_ptr(thread_runq);
}

static inline unsigned int
thread_runq_cpu(struct thread_runq *runq)
{
    return runq->cpu;
}

static void
thread_runq_add(struct thread_runq *runq, struct thread *thread)
{
    const struct thread_sched_ops *ops;

    assert(!cpu_intr_enabled());
    spinlock_assert_locked(&runq->lock);
    assert(!thread->in_runq);

    ops = thread_get_real_sched_ops(thread);
    ops->add(runq, thread);

    if (runq->nr_threads == 0) {
        cpumap_clear_atomic(&thread_idle_runqs, thread_runq_cpu(runq));
    }

    runq->nr_threads++;

    if (thread_real_sched_class(thread)
        < thread_real_sched_class(runq->current)) {
        thread_set_flag(runq->current, THREAD_YIELD);
    }

    thread->runq = runq;
    thread->in_runq = true;
}

static void
thread_runq_remove(struct thread_runq *runq, struct thread *thread)
{
    const struct thread_sched_ops *ops;

    assert(!cpu_intr_enabled());
    spinlock_assert_locked(&runq->lock);
    assert(thread->in_runq);

    runq->nr_threads--;

    if (runq->nr_threads == 0) {
        cpumap_set_atomic(&thread_idle_runqs, thread_runq_cpu(runq));
    }

    ops = thread_get_real_sched_ops(thread);
    ops->remove(runq, thread);

    thread->in_runq = false;
}

static void
thread_runq_put_prev(struct thread_runq *runq, struct thread *thread)
{
    const struct thread_sched_ops *ops;

    assert(!cpu_intr_enabled());
    spinlock_assert_locked(&runq->lock);

    ops = thread_get_real_sched_ops(thread);

    if (ops->put_prev != NULL) {
        ops->put_prev(runq, thread);
    }
}

static struct thread *
thread_runq_get_next(struct thread_runq *runq)
{
    struct thread *thread;
    unsigned int i;

    assert(!cpu_intr_enabled());
    spinlock_assert_locked(&runq->lock);

    for (i = 0; i < ARRAY_SIZE(thread_sched_ops); i++) {
        thread = thread_sched_ops[i].get_next(runq);

        if (thread != NULL) {
            runq->current = thread;
            return thread;
        }
    }

    /* The idle class should never be empty */
    panic("thread: unable to find next thread");
}

static void
thread_runq_set_next(struct thread_runq *runq, struct thread *thread)
{
    const struct thread_sched_ops *ops;

    ops = thread_get_real_sched_ops(thread);

    if (ops->set_next != NULL) {
        ops->set_next(runq, thread);
    }

    runq->current = thread;
}

static void
thread_runq_wakeup(struct thread_runq *runq, struct thread *thread)
{
    assert(!cpu_intr_enabled());
    spinlock_assert_locked(&runq->lock);
    assert(thread->state == THREAD_RUNNING);

    thread_runq_add(runq, thread);

    if ((runq != thread_runq_local())
        && thread_test_flag(runq->current, THREAD_YIELD)) {
        cpu_send_thread_schedule(thread_runq_cpu(runq));
    }
}

static void
thread_runq_wakeup_balancer(struct thread_runq *runq)
{
    if (runq->balancer->state == THREAD_RUNNING) {
        return;
    }

    thread_clear_wchan(runq->balancer);
    runq->balancer->state = THREAD_RUNNING;
    thread_runq_wakeup(runq, runq->balancer);
}

static void
thread_runq_schedule_prepare(struct thread *thread)
{
    pmap_load(thread->task->map->pmap);
}

static struct thread_runq *
thread_runq_schedule(struct thread_runq *runq)
{
    struct thread *prev, *next;

    prev = thread_self();

    assert(prev->preempt == THREAD_SUSPEND_PREEMPT_LEVEL);
    assert(!cpu_intr_enabled());
    spinlock_assert_locked(&runq->lock);

    llsync_report_context_switch();

    thread_clear_flag(prev, THREAD_YIELD);
    thread_runq_put_prev(runq, prev);

    if (prev->state != THREAD_RUNNING) {
        thread_runq_remove(runq, prev);

        if ((runq->nr_threads == 0) && (prev != runq->balancer)) {
            thread_runq_wakeup_balancer(runq);
        }
    }

    next = thread_runq_get_next(runq);
    assert((next != runq->idler) || (runq->nr_threads == 0));
    assert(next->preempt == THREAD_SUSPEND_PREEMPT_LEVEL);

    if (likely(prev != next)) {
        /*
         * That's where the true context switch occurs. The next thread must
         * unlock the run queue and reenable preemption. Note that unlocking
         * and locking the run queue again is equivalent to a full memory
         * barrier.
         */
        tcb_switch(&prev->tcb, &next->tcb);

        /*
         * The thread is dispatched on a processor once again.
         *
         * Keep in mind the system state may have changed a lot since this
         * function was called. In particular, the next thread may have been
         * destroyed, and must not be referenced any more.
         */
        barrier();

        /* The thread might have been moved to another processor */
        runq = thread_runq_local();

        thread_runq_schedule_prepare(prev);
    }

    assert(prev->preempt == THREAD_SUSPEND_PREEMPT_LEVEL);
    assert(!cpu_intr_enabled());
    spinlock_assert_locked(&runq->lock);
    return runq;
}

static void
thread_runq_double_lock(struct thread_runq *a, struct thread_runq *b)
{
    assert(!cpu_intr_enabled());
    assert(!thread_preempt_enabled());
    assert(a != b);

    if (a->cpu < b->cpu) {
        spinlock_lock(&a->lock);
        spinlock_lock(&b->lock);
    } else {
        spinlock_lock(&b->lock);
        spinlock_lock(&a->lock);
    }
}

static struct thread_runq *
thread_sched_rt_select_runq(struct thread *thread)
{
    struct thread_runq *runq;
    int i;

    /*
     * Real-time tasks are commonly configured to run on one specific
     * processor only.
     */
    i = cpumap_find_first(&thread->cpumap);
    assert(i >= 0);
    assert(cpumap_test(&thread_active_runqs, i));

    runq = percpu_ptr(thread_runq, i);
    spinlock_lock(&runq->lock);
    return runq;
}

static void
thread_sched_rt_add(struct thread_runq *runq, struct thread *thread)
{
    struct thread_rt_runq *rt_runq;
    struct list *threads;

    rt_runq = &runq->rt_runq;
    threads = &rt_runq->threads[thread_real_priority(thread)];
    list_insert_tail(threads, &thread->rt_data.node);

    if (list_singular(threads)) {
        rt_runq->bitmap |= (1ULL << thread_real_priority(thread));
    }

    if ((thread_real_sched_class(thread)
         == thread_real_sched_class(runq->current))
        && (thread_real_priority(thread)
            > thread_real_priority(runq->current))) {
        thread_set_flag(runq->current, THREAD_YIELD);
    }
}

static void
thread_sched_rt_remove(struct thread_runq *runq, struct thread *thread)
{
    struct thread_rt_runq *rt_runq;
    struct list *threads;

    rt_runq = &runq->rt_runq;
    threads = &rt_runq->threads[thread_real_priority(thread)];
    list_remove(&thread->rt_data.node);

    if (list_empty(threads)) {
        rt_runq->bitmap &= ~(1ULL << thread_real_priority(thread));
    }
}

static void
thread_sched_rt_put_prev(struct thread_runq *runq, struct thread *thread)
{
    thread_sched_rt_add(runq, thread);
}

static struct thread *
thread_sched_rt_get_next(struct thread_runq *runq)
{
    struct thread_rt_runq *rt_runq;
    struct thread *thread;
    struct list *threads;
    unsigned int priority;

    rt_runq = &runq->rt_runq;

    if (rt_runq->bitmap == 0) {
        return NULL;
    }

    priority = THREAD_SCHED_RT_PRIO_MAX - __builtin_clz(rt_runq->bitmap);
    threads = &rt_runq->threads[priority];
    assert(!list_empty(threads));
    thread = list_first_entry(threads, struct thread, rt_data.node);
    thread_sched_rt_remove(runq, thread);
    return thread;
}

static void
thread_sched_rt_reset_priority(struct thread *thread, unsigned short priority)
{
    assert(priority <= THREAD_SCHED_RT_PRIO_MAX);
    thread->rt_data.time_slice = THREAD_DEFAULT_RR_TIME_SLICE;
}

static unsigned int
thread_sched_rt_get_global_priority(unsigned short priority)
{
    return THREAD_SCHED_GLOBAL_PRIO_RT + priority;
}

static void
thread_sched_rt_set_next(struct thread_runq *runq, struct thread *thread)
{
    thread_sched_rt_remove(runq, thread);
}

static void
thread_sched_rt_tick(struct thread_runq *runq, struct thread *thread)
{
    (void)runq;

    if (thread_real_sched_policy(thread) != THREAD_SCHED_POLICY_RR) {
        return;
    }

    thread->rt_data.time_slice--;

    if (thread->rt_data.time_slice > 0) {
        return;
    }

    thread->rt_data.time_slice = THREAD_DEFAULT_RR_TIME_SLICE;
    thread_set_flag(thread, THREAD_YIELD);
}

static inline unsigned short
thread_sched_fs_prio2weight(unsigned short priority)
{
    return ((priority + 1) * THREAD_FS_ROUND_SLICE_BASE);
}

static struct thread_runq *
thread_sched_fs_select_runq(struct thread *thread)
{
    struct thread_runq *runq, *tmp;
    long delta;
    int i;

    cpumap_for_each(&thread_idle_runqs, i) {
        if (!cpumap_test(&thread->cpumap, i)) {
            continue;
        }

        runq = percpu_ptr(thread_runq, i);

        spinlock_lock(&runq->lock);

        /* The run queue really is idle, return it */
        if (runq->current == runq->idler) {
            goto out;
        }

        spinlock_unlock(&runq->lock);
    }

    runq = NULL;

    cpumap_for_each(&thread_active_runqs, i) {
        if (!cpumap_test(&thread->cpumap, i)) {
            continue;
        }

        tmp = percpu_ptr(thread_runq, i);

        spinlock_lock(&tmp->lock);

        if (runq == NULL) {
            runq = tmp;
            continue;
        }

        /* A run queue may have become idle */
        if (tmp->current == tmp->idler) {
            spinlock_unlock(&runq->lock);
            runq = tmp;
            goto out;
        }

        /*
         * The run queue isn't idle, but there are no fair-scheduling thread,
         * which means there are real-time threads.
         */
        if (tmp->fs_weight == 0) {
            spinlock_unlock(&tmp->lock);
            continue;
        }

        delta = (long)(tmp->fs_round - runq->fs_round);

        /* Look for the least loaded of the run queues in the highest round */
        if ((delta > 0)
            || ((delta == 0) && (tmp->fs_weight < runq->fs_weight))) {
            spinlock_unlock(&runq->lock);
            runq = tmp;
            continue;
        }

        spinlock_unlock(&tmp->lock);
    }

    assert(runq != NULL);

out:
    return runq;
}

static unsigned int
thread_sched_fs_enqueue_scale(unsigned int work, unsigned int old_weight,
                              unsigned int new_weight)
{
    assert(old_weight != 0);

#ifndef __LP64__
    if (likely((work < 0x10000) && (new_weight < 0x10000))) {
        return (work * new_weight) / old_weight;
    }
#endif /* __LP64__ */

    return (unsigned int)(((unsigned long long)work * new_weight) / old_weight);
}

static void
thread_sched_fs_enqueue(struct thread_fs_runq *fs_runq, unsigned long round,
                        struct thread *thread)
{
    struct thread_fs_group *group, *tmp;
    struct list *node, *init_node;
    unsigned int group_weight, total_weight;

    assert(thread->fs_data.fs_runq == NULL);
    assert(thread->fs_data.work <= thread->fs_data.weight);

    group = &fs_runq->group_array[thread_real_priority(thread)];
    group_weight = group->weight + thread->fs_data.weight;
    total_weight = fs_runq->weight + thread->fs_data.weight;
    node = (group->weight == 0)
           ? list_last(&fs_runq->groups)
           : list_prev(&group->node);
    init_node = node;

    while (!list_end(&fs_runq->groups, node)) {
        tmp = list_entry(node, struct thread_fs_group, node);

        if (tmp->weight >= group_weight) {
            break;
        }

        node = list_prev(node);
    }

    if (group->weight == 0) {
        list_insert_after(node, &group->node);
    } else if (node != init_node) {
        list_remove(&group->node);
        list_insert_after(node, &group->node);
    }

    /*
     * XXX Unfairness can occur if the run queue round wraps around and the
     * thread is "lucky" enough to have the same round value. This should be
     * rare and harmless otherwise.
     */
    if (thread->fs_data.round == round) {
        fs_runq->work += thread->fs_data.work;
        group->work += thread->fs_data.work;
    } else {
        unsigned int group_work, thread_work;

        if (fs_runq->weight == 0) {
            thread_work = 0;
        } else {
            group_work = (group->weight == 0)
                         ? thread_sched_fs_enqueue_scale(fs_runq->work,
                                                         fs_runq->weight,
                                                         thread->fs_data.weight)
                         : thread_sched_fs_enqueue_scale(group->work,
                                                         group->weight,
                                                         group_weight);
            thread_work = group_work - group->work;
            fs_runq->work += thread_work;
            group->work = group_work;
        }

        thread->fs_data.round = round;
        thread->fs_data.work = thread_work;
    }

    fs_runq->nr_threads++;
    fs_runq->weight = total_weight;
    group->weight = group_weight;

    /* Insert at the front of the group to improve interactivity */
    list_insert_head(&group->threads, &thread->fs_data.group_node);
    list_insert_tail(&fs_runq->threads, &thread->fs_data.runq_node);
    thread->fs_data.fs_runq = fs_runq;
}

static void
thread_sched_fs_restart(struct thread_runq *runq)
{
    struct thread_fs_runq *fs_runq;
    struct list *node;

    fs_runq = runq->fs_runq_active;
    node = list_first(&fs_runq->groups);
    assert(node != NULL);
    fs_runq->current = list_entry(node, struct thread_fs_group, node);

    if (thread_real_sched_class(runq->current) == THREAD_SCHED_CLASS_FS) {
        thread_set_flag(runq->current, THREAD_YIELD);
    }
}

static void
thread_sched_fs_add(struct thread_runq *runq, struct thread *thread)
{
    unsigned int total_weight;

    if (runq->fs_weight == 0) {
        runq->fs_round = thread_fs_highest_round;
    }

    total_weight = runq->fs_weight + thread->fs_data.weight;

    /* TODO Limit the maximum number of threads to prevent this situation */
    if (total_weight < runq->fs_weight) {
        panic("thread: weight overflow");
    }

    runq->fs_weight = total_weight;
    thread_sched_fs_enqueue(runq->fs_runq_active, runq->fs_round, thread);
    thread_sched_fs_restart(runq);
}

static void
thread_sched_fs_dequeue(struct thread *thread)
{
    struct thread_fs_runq *fs_runq;
    struct thread_fs_group *group, *tmp;
    struct list *node, *init_node;

    assert(thread->fs_data.fs_runq != NULL);

    fs_runq = thread->fs_data.fs_runq;
    group = &fs_runq->group_array[thread_real_priority(thread)];

    thread->fs_data.fs_runq = NULL;
    list_remove(&thread->fs_data.runq_node);
    list_remove(&thread->fs_data.group_node);
    fs_runq->work -= thread->fs_data.work;
    group->work -= thread->fs_data.work;
    fs_runq->weight -= thread->fs_data.weight;
    group->weight -= thread->fs_data.weight;
    fs_runq->nr_threads--;

    if (group->weight == 0) {
        list_remove(&group->node);
    } else {
        node = list_next(&group->node);
        init_node = node;

        while (!list_end(&fs_runq->groups, node)) {
            tmp = list_entry(node, struct thread_fs_group, node);

            if (tmp->weight <= group->weight) {
                break;
            }

            node = list_next(node);
        }

        if (node != init_node) {
            list_remove(&group->node);
            list_insert_before(node, &group->node);
        }
    }
}

static void
thread_sched_fs_remove(struct thread_runq *runq, struct thread *thread)
{
    struct thread_fs_runq *fs_runq;

    runq->fs_weight -= thread->fs_data.weight;
    fs_runq = thread->fs_data.fs_runq;
    thread_sched_fs_dequeue(thread);

    if (fs_runq == runq->fs_runq_active) {
        if (fs_runq->nr_threads == 0) {
            thread_runq_wakeup_balancer(runq);
        } else {
            thread_sched_fs_restart(runq);
        }
    }
}

static void
thread_sched_fs_deactivate(struct thread_runq *runq, struct thread *thread)
{
    assert(thread->fs_data.fs_runq == runq->fs_runq_active);
    assert(thread->fs_data.round == runq->fs_round);

    thread_sched_fs_dequeue(thread);
    thread->fs_data.round++;
    thread->fs_data.work -= thread->fs_data.weight;
    thread_sched_fs_enqueue(runq->fs_runq_expired, runq->fs_round + 1, thread);

    if (runq->fs_runq_active->nr_threads == 0) {
        thread_runq_wakeup_balancer(runq);
    }
}

static void
thread_sched_fs_put_prev(struct thread_runq *runq, struct thread *thread)
{
    struct thread_fs_runq *fs_runq;
    struct thread_fs_group *group;

    fs_runq = runq->fs_runq_active;
    group = &fs_runq->group_array[thread_real_priority(thread)];
    list_insert_tail(&group->threads, &thread->fs_data.group_node);

    if (thread->fs_data.work >= thread->fs_data.weight) {
        thread_sched_fs_deactivate(runq, thread);
    }
}

static int
thread_sched_fs_ratio_exceeded(struct thread_fs_group *current,
                               struct thread_fs_group *next)
{
    unsigned long long a, b;

#ifndef __LP64__
    unsigned int ia, ib;

    if (likely((current->weight < 0x10000) && (next->weight < 0x10000))) {
        ia = (current->work + 1) * next->weight;
        ib = (next->work + 1) * current->weight;
        return ia > ib;
    }
#endif /* __LP64__ */

    a = ((unsigned long long)current->work + 1) * next->weight;
    b = ((unsigned long long)next->work + 1) * current->weight;
    return a > b;
}

static struct thread *
thread_sched_fs_get_next(struct thread_runq *runq)
{
    struct thread_fs_runq *fs_runq;
    struct thread_fs_group *group, *next;
    struct thread *thread;
    struct list *node;

    fs_runq = runq->fs_runq_active;

    if (fs_runq->nr_threads == 0) {
        return NULL;
    }

    group = fs_runq->current;
    node = list_next(&group->node);

    if (list_end(&fs_runq->groups, node)) {
        node = list_first(&fs_runq->groups);
        group = list_entry(node, struct thread_fs_group, node);
    } else {
        next = list_entry(node, struct thread_fs_group, node);

        if (thread_sched_fs_ratio_exceeded(group, next)) {
            group = next;
        } else {
            node = list_first(&fs_runq->groups);
            group = list_entry(node, struct thread_fs_group, node);
        }
    }

    fs_runq->current = group;
    node = list_first(&group->threads);
    thread = list_entry(node, struct thread, fs_data.group_node);
    list_remove(node);
    return thread;
}

static void
thread_sched_fs_reset_priority(struct thread *thread, unsigned short priority)
{
    assert(priority <= THREAD_SCHED_FS_PRIO_MAX);
    thread->fs_data.fs_runq = NULL;
    thread->fs_data.round = 0;
    thread->fs_data.weight = thread_sched_fs_prio2weight(priority);
    thread->fs_data.work = 0;
}

static void
thread_sched_fs_update_priority(struct thread *thread, unsigned short priority)
{
    assert(priority <= THREAD_SCHED_FS_PRIO_MAX);
    thread->fs_data.weight = thread_sched_fs_prio2weight(priority);

    if (thread->fs_data.work >= thread->fs_data.weight) {
        thread->fs_data.work = thread->fs_data.weight;
    }
}

static unsigned int
thread_sched_fs_get_global_priority(unsigned short priority)
{
    (void)priority;
    return THREAD_SCHED_GLOBAL_PRIO_FS;
}

static void
thread_sched_fs_set_next(struct thread_runq *runq, struct thread *thread)
{
    (void)runq;

    list_remove(&thread->fs_data.group_node);
}

static void
thread_sched_fs_tick(struct thread_runq *runq, struct thread *thread)
{
    struct thread_fs_runq *fs_runq;
    struct thread_fs_group *group;

    fs_runq = runq->fs_runq_active;
    fs_runq->work++;
    group = &fs_runq->group_array[thread_real_priority(thread)];
    group->work++;
    thread_set_flag(thread, THREAD_YIELD);
    thread->fs_data.work++;
}

static void
thread_sched_fs_start_next_round(struct thread_runq *runq)
{
    struct thread_fs_runq *tmp;
    long delta;

    tmp = runq->fs_runq_expired;
    runq->fs_runq_expired = runq->fs_runq_active;
    runq->fs_runq_active = tmp;

    if (runq->fs_runq_active->nr_threads != 0) {
        runq->fs_round++;
        delta = (long)(runq->fs_round - thread_fs_highest_round);

        if (delta > 0) {
            thread_fs_highest_round = runq->fs_round;
        }

        thread_sched_fs_restart(runq);
    }
}

/*
 * Check that a remote run queue satisfies the minimum migration requirements.
 */
static int
thread_sched_fs_balance_eligible(struct thread_runq *runq,
                                 unsigned long highest_round)
{
    unsigned int nr_threads;

    if (runq->fs_weight == 0) {
        return 0;
    }

    if ((runq->fs_round != highest_round)
        && (runq->fs_round != (highest_round - 1))) {
        return 0;
    }

    nr_threads = runq->fs_runq_active->nr_threads
                 + runq->fs_runq_expired->nr_threads;

    if ((nr_threads == 0)
        || ((nr_threads == 1)
            && (thread_real_sched_class(runq->current)
                == THREAD_SCHED_CLASS_FS))) {
        return 0;
    }

    return 1;
}

/*
 * Try to find the most suitable run queue from which to pull threads.
 */
static struct thread_runq *
thread_sched_fs_balance_scan(struct thread_runq *runq,
                             unsigned long highest_round)
{
    struct thread_runq *remote_runq, *tmp;
    unsigned long flags;
    int i;

    remote_runq = NULL;

    thread_preempt_disable();
    cpu_intr_save(&flags);

    cpumap_for_each(&thread_active_runqs, i) {
        tmp = percpu_ptr(thread_runq, i);

        if (tmp == runq) {
            continue;
        }

        spinlock_lock(&tmp->lock);

        if (!thread_sched_fs_balance_eligible(tmp, highest_round)) {
            spinlock_unlock(&tmp->lock);
            continue;
        }

        if (remote_runq == NULL) {
            remote_runq = tmp;
            continue;
        }

        if (tmp->fs_weight > remote_runq->fs_weight) {
            spinlock_unlock(&remote_runq->lock);
            remote_runq = tmp;
            continue;
        }

        spinlock_unlock(&tmp->lock);
    }

    if (remote_runq != NULL) {
        spinlock_unlock(&remote_runq->lock);
    }

    cpu_intr_restore(flags);
    thread_preempt_enable();

    return remote_runq;
}

static unsigned int
thread_sched_fs_balance_pull(struct thread_runq *runq,
                             struct thread_runq *remote_runq,
                             struct thread_fs_runq *fs_runq,
                             unsigned int nr_pulls)
{
    struct thread *thread, *tmp;
    int cpu;

    cpu = thread_runq_cpu(runq);

    list_for_each_entry_safe(&fs_runq->threads, thread, tmp,
                             fs_data.runq_node) {
        if (thread == remote_runq->current) {
            continue;
        }

        /*
         * The pinned counter is changed without explicit synchronization.
         * However, it can only be changed by its owning thread. As threads
         * currently running aren't considered for migration, the thread had
         * to be preempted and invoke the scheduler. Since balancer threads
         * acquire the run queue lock, there is strong ordering between
         * changing the pinned counter and setting the current thread of a
         * run queue.
         */
        if (thread->pinned) {
            continue;
        }

        if (!cpumap_test(&thread->cpumap, cpu)) {
            continue;
        }

        /*
         * Make sure at least one thread is pulled if possible. If one or more
         * thread has already been pulled, take weights into account.
         */
        if ((nr_pulls != 0)
            && ((runq->fs_weight + thread->fs_data.weight)
                > (remote_runq->fs_weight - thread->fs_data.weight))) {
            break;
        }

        thread_runq_remove(remote_runq, thread);

        /* Don't discard the work already accounted for */
        thread->fs_data.round = runq->fs_round;

        thread_runq_add(runq, thread);
        nr_pulls++;

        if (nr_pulls == THREAD_MAX_MIGRATIONS) {
            break;
        }
    }

    return nr_pulls;
}

static unsigned int
thread_sched_fs_balance_migrate(struct thread_runq *runq,
                                struct thread_runq *remote_runq,
                                unsigned long highest_round)
{
    unsigned int nr_pulls;

    nr_pulls = 0;

    if (!thread_sched_fs_balance_eligible(remote_runq, highest_round)) {
        goto out;
    }

    nr_pulls = thread_sched_fs_balance_pull(runq, remote_runq,
                                            remote_runq->fs_runq_active, 0);

    if (nr_pulls == THREAD_MAX_MIGRATIONS) {
        goto out;
    }

    /*
     * Threads in the expired queue of a processor in round highest are
     * actually in round highest + 1.
     */
    if (remote_runq->fs_round != highest_round) {
        nr_pulls = thread_sched_fs_balance_pull(runq, remote_runq,
                                                remote_runq->fs_runq_expired,
                                                nr_pulls);
    }

out:
    return nr_pulls;
}

/*
 * Inter-processor load balancing for fair-scheduling threads.
 *
 * Preemption must be disabled, and the local run queue must be locked when
 * calling this function. If balancing actually occurs, the lock will be
 * released and preemption enabled when needed.
 */
static void
thread_sched_fs_balance(struct thread_runq *runq, unsigned long *flags)
{
    struct thread_runq *remote_runq;
    unsigned long highest_round;
    unsigned int nr_migrations;
    int i;

    /*
     * Grab the highest round now and only use the copy so the value is stable
     * during the balancing operation.
     */
    highest_round = thread_fs_highest_round;

    if ((runq->fs_round != highest_round)
        && (runq->fs_runq_expired->nr_threads != 0)) {
        goto no_migration;
    }

    spinlock_unlock_intr_restore(&runq->lock, *flags);
    thread_preempt_enable();

    remote_runq = thread_sched_fs_balance_scan(runq, highest_round);

    if (remote_runq != NULL) {
        thread_preempt_disable();
        cpu_intr_save(flags);
        thread_runq_double_lock(runq, remote_runq);
        nr_migrations = thread_sched_fs_balance_migrate(runq, remote_runq,
                                                        highest_round);
        spinlock_unlock(&remote_runq->lock);

        if (nr_migrations != 0) {
            return;
        }

        spinlock_unlock_intr_restore(&runq->lock, *flags);
        thread_preempt_enable();
    }

    /*
     * The scan or the migration failed. As a fallback, make another, simpler
     * pass on every run queue, and stop as soon as at least one thread could
     * be successfully pulled.
     */

    cpumap_for_each(&thread_active_runqs, i) {
        remote_runq = percpu_ptr(thread_runq, i);

        if (remote_runq == runq) {
            continue;
        }

        thread_preempt_disable();
        cpu_intr_save(flags);
        thread_runq_double_lock(runq, remote_runq);
        nr_migrations = thread_sched_fs_balance_migrate(runq, remote_runq,
                                                        highest_round);
        spinlock_unlock(&remote_runq->lock);

        if (nr_migrations != 0) {
            return;
        }

        spinlock_unlock_intr_restore(&runq->lock, *flags);
        thread_preempt_enable();
    }

    thread_preempt_disable();
    spinlock_lock_intr_save(&runq->lock, flags);

no_migration:

    /*
     * No thread could be migrated. Check the active run queue, as another
     * processor might have added threads while the balancer was running.
     * If the run queue is still empty, switch to the next round. The run
     * queue lock must remain held until the next scheduling decision to
     * prevent a remote balancer thread from stealing active threads.
     */
    if (runq->fs_runq_active->nr_threads == 0) {
        thread_sched_fs_start_next_round(runq);
    }
}

static struct thread_runq *
thread_sched_idle_select_runq(struct thread *thread)
{
    (void)thread;
    panic("thread: idler threads cannot be awaken");
}

static void __noreturn
thread_sched_idle_panic(void)
{
    panic("thread: only idle threads are allowed in the idle class");
}

static void
thread_sched_idle_add(struct thread_runq *runq, struct thread *thread)
{
    (void)runq;
    (void)thread;

    thread_sched_idle_panic();
}

static void
thread_sched_idle_remove(struct thread_runq *runq, struct thread *thread)
{
    (void)runq;
    (void)thread;

    thread_sched_idle_panic();
}

static struct thread *
thread_sched_idle_get_next(struct thread_runq *runq)
{
    return runq->idler;
}

static unsigned int
thread_sched_idle_get_global_priority(unsigned short priority)
{
    (void)priority;
    return THREAD_SCHED_GLOBAL_PRIO_IDLE;
}

static const struct thread_sched_ops thread_sched_ops[THREAD_NR_SCHED_CLASSES]
    = {
    [THREAD_SCHED_CLASS_RT] = {
        .select_runq = thread_sched_rt_select_runq,
        .add = thread_sched_rt_add,
        .remove = thread_sched_rt_remove,
        .put_prev = thread_sched_rt_put_prev,
        .get_next = thread_sched_rt_get_next,
        .reset_priority = thread_sched_rt_reset_priority,
        .update_priority = NULL,
        .get_global_priority = thread_sched_rt_get_global_priority,
        .set_next = thread_sched_rt_set_next,
        .tick = thread_sched_rt_tick,
    },
    [THREAD_SCHED_CLASS_FS] = {
        .select_runq = thread_sched_fs_select_runq,
        .add = thread_sched_fs_add,
        .remove = thread_sched_fs_remove,
        .put_prev = thread_sched_fs_put_prev,
        .get_next = thread_sched_fs_get_next,
        .reset_priority = thread_sched_fs_reset_priority,
        .update_priority = thread_sched_fs_update_priority,
        .get_global_priority = thread_sched_fs_get_global_priority,
        .set_next = thread_sched_fs_set_next,
        .tick = thread_sched_fs_tick,
    },
    [THREAD_SCHED_CLASS_IDLE] = {
        .select_runq = thread_sched_idle_select_runq,
        .add = thread_sched_idle_add,
        .remove = thread_sched_idle_remove,
        .put_prev = NULL,
        .get_next = thread_sched_idle_get_next,
        .reset_priority = NULL,
        .update_priority = NULL,
        .get_global_priority = thread_sched_idle_get_global_priority,
        .set_next = NULL,
        .tick = NULL,
    },
};

static void
thread_set_user_sched_policy(struct thread *thread, unsigned char sched_policy)
{
    thread->user_sched_data.sched_policy = sched_policy;
}

static void
thread_set_user_sched_class(struct thread *thread, unsigned char sched_class)
{
    thread->user_sched_data.sched_class = sched_class;
}

static void
thread_set_user_priority(struct thread *thread, unsigned short priority)
{
    const struct thread_sched_ops *ops;

    ops = thread_get_user_sched_ops(thread);

    thread->user_sched_data.priority = priority;
    thread->user_sched_data.global_priority
        = ops->get_global_priority(priority);
}

static void
thread_update_user_priority(struct thread *thread, unsigned short priority)
{
    thread_set_user_priority(thread, priority);
}

static void
thread_set_real_sched_policy(struct thread *thread, unsigned char sched_policy)
{
    thread->real_sched_data.sched_policy = sched_policy;
}

static void
thread_set_real_sched_class(struct thread *thread, unsigned char sched_class)
{
    thread->real_sched_data.sched_class = sched_class;
}

static void
thread_set_real_priority(struct thread *thread, unsigned short priority)
{
    const struct thread_sched_ops *ops;

    ops = thread_get_real_sched_ops(thread);

    thread->real_sched_data.priority = priority;
    thread->real_sched_data.global_priority
        = ops->get_global_priority(priority);

    if (ops->reset_priority != NULL) {
        ops->reset_priority(thread, priority);
    }
}

static void
thread_update_real_priority(struct thread *thread, unsigned short priority)
{
    const struct thread_sched_ops *ops;

    ops = thread_get_real_sched_ops(thread);

    thread->real_sched_data.priority = priority;
    thread->real_sched_data.global_priority
        = ops->get_global_priority(priority);

    if (ops->update_priority != NULL) {
        ops->update_priority(thread, priority);
    }
}

static void
thread_reset_real_priority(struct thread *thread)
{
    const struct thread_sched_ops *ops;
    struct thread_sched_data *user, *real;

    user = &thread->user_sched_data;
    real = &thread->real_sched_data;
    *real = *user;
    thread->boosted = false;

    ops = thread_get_user_sched_ops(thread);

    if (ops->reset_priority != NULL) {
        ops->reset_priority(thread, real->priority);
    }
}

static void __init
thread_bootstrap_common(unsigned int cpu)
{
    struct thread *booter;

    cpumap_set(&thread_active_runqs, cpu);

    /* Initialize only what's needed during bootstrap */
    booter = &thread_booters[cpu];
    booter->nr_refs = 0; /* Make sure booters aren't destroyed */
    booter->flags = 0;
    booter->intr = 0;
    booter->preempt = 1;
    cpumap_fill(&booter->cpumap);
    thread_set_user_sched_policy(booter, THREAD_SCHED_POLICY_IDLE);
    thread_set_user_sched_class(booter, THREAD_SCHED_CLASS_IDLE);
    thread_set_user_priority(booter, 0);
    thread_reset_real_priority(booter);
    memset(booter->tsd, 0, sizeof(booter->tsd));
    booter->task = kernel_task;
    snprintf(booter->name, sizeof(booter->name),
             THREAD_KERNEL_PREFIX "thread_boot/%u", cpu);
    thread_runq_init(percpu_ptr(thread_runq, cpu), cpu, booter);
}

void __init
thread_bootstrap(void)
{
    cpumap_zero(&thread_active_runqs);
    cpumap_zero(&thread_idle_runqs);

    thread_fs_highest_round = THREAD_FS_INITIAL_ROUND;

    tcb_set_current(&thread_booters[0].tcb);
    thread_bootstrap_common(0);
}

void __init
thread_ap_bootstrap(void)
{
    tcb_set_current(&thread_booters[cpu_id()].tcb);
}

static void
thread_main(void)
{
    struct thread *thread;

    assert(!cpu_intr_enabled());
    assert(!thread_preempt_enabled());

    thread = thread_self();
    thread_runq_schedule_prepare(thread);

    spinlock_unlock(&thread_runq_local()->lock);
    cpu_intr_enable();
    thread_preempt_enable();

    thread->fn(thread->arg);
    thread_exit();
}

static void
thread_destroy_tsd(struct thread *thread)
{
    void *ptr;
    unsigned int i;

    i = 0;

    while (i < thread_nr_keys) {
        if ((thread->tsd[i] == NULL) || (thread_dtors[i] == NULL)) {
            i++;
            continue;
        }

        /*
         * Follow the POSIX description of TSD: set the key to NULL before
         * calling the destructor and repeat as long as it's not NULL.
         */
        ptr = thread->tsd[i];
        thread->tsd[i] = NULL;
        thread_dtors[i](ptr);

        if (thread->tsd[i] == NULL) {
            i++;
        }
    }
}

static int
thread_init(struct thread *thread, void *stack,
            const struct thread_attr *attr,
            void (*fn)(void *), void *arg)
{
    struct thread *caller;
    struct task *task;
    struct cpumap *cpumap;
    int error;

    caller = thread_self();

    task = (attr->task == NULL) ? caller->task : attr->task;
    cpumap = (attr->cpumap == NULL) ? &caller->cpumap : attr->cpumap;
    assert(attr->policy < ARRAY_SIZE(thread_policy_table));

    thread->nr_refs = 1;
    thread->flags = 0;
    thread->runq = NULL;
    thread->in_runq = false;
    thread_set_wchan(thread, thread, "init");
    thread->state = THREAD_SLEEPING;
    thread->priv_sleepq = sleepq_create();

    if (thread->priv_sleepq == NULL) {
        error = ERROR_NOMEM;
        goto error_sleepq;
    }

    thread->priv_turnstile = turnstile_create();

    if (thread->priv_turnstile == NULL) {
        error = ERROR_NOMEM;
        goto error_turnstile;
    }

    turnstile_td_init(&thread->turnstile_td);
    thread->last_cond = NULL;
    thread->propagate_priority = false;
    thread->intr = 0;
    thread->preempt = THREAD_SUSPEND_PREEMPT_LEVEL;
    thread->pinned = 0;
    thread->llsync_read = 0;
    cpumap_copy(&thread->cpumap, cpumap);
    thread_set_user_sched_policy(thread, attr->policy);
    thread_set_user_sched_class(thread, thread_policy_to_class(attr->policy));
    thread_set_user_priority(thread, attr->priority);
    thread_reset_real_priority(thread);
    memset(thread->tsd, 0, sizeof(thread->tsd));
    mutex_init(&thread->join_lock);
    condition_init(&thread->join_cond);
    thread->exited = 0;
    thread->task = task;
    thread->stack = stack;
    strlcpy(thread->name, attr->name, sizeof(thread->name));
    thread->fn = fn;
    thread->arg = arg;

    if (attr->flags & THREAD_ATTR_DETACHED) {
        thread->flags |= THREAD_DETACHED;
    }

    error = tcb_init(&thread->tcb, stack, thread_main);

    if (error) {
        goto error_tcb;
    }

    task_add_thread(task, thread);

    return 0;

error_tcb:
    thread_destroy_tsd(thread);
    turnstile_destroy(thread->priv_turnstile);
error_turnstile:
    sleepq_destroy(thread->priv_sleepq);
error_sleepq:
    return error;
}

static struct thread_runq *
thread_lock_runq(struct thread *thread, unsigned long *flags)
{
    struct thread_runq *runq;

    for (;;) {
        runq = thread->runq;

        spinlock_lock_intr_save(&runq->lock, flags);

        if (runq == thread->runq) {
            return runq;
        }

        spinlock_unlock_intr_restore(&runq->lock, *flags);
    }
}

static void
thread_unlock_runq(struct thread_runq *runq, unsigned long flags)
{
    spinlock_unlock_intr_restore(&runq->lock, flags);
}

#ifdef X15_THREAD_STACK_GUARD

#include <machine/pmap.h>
#include <vm/vm_kmem.h>
#include <vm/vm_page.h>

static void *
thread_alloc_stack(void)
{
    struct vm_page *first_page, *last_page;
    phys_addr_t first_pa, last_pa;
    size_t stack_size;
    uintptr_t va;
    void *mem;
    int error;

    stack_size = vm_page_round(STACK_SIZE);
    mem = vm_kmem_alloc((PAGE_SIZE * 2) + stack_size);

    if (mem == NULL) {
        return NULL;
    }

    va = (uintptr_t)mem;

    /*
     * TODO Until memory protection is implemented, use the pmap system
     * to remove mappings.
     */
    error = pmap_kextract(va, &first_pa);
    assert(!error);

    error = pmap_kextract(va + PAGE_SIZE + stack_size, &last_pa);
    assert(!error);

    first_page = vm_page_lookup(first_pa);
    assert(first_page != NULL);

    last_page = vm_page_lookup(last_pa);
    assert(last_page != NULL);

    pmap_remove(kernel_pmap, va, cpumap_all());
    pmap_remove(kernel_pmap, va + PAGE_SIZE + stack_size, cpumap_all());
    pmap_update(kernel_pmap);

    vm_page_free(first_page, 0);
    vm_page_free(last_page, 0);

    return (char *)va + PAGE_SIZE;
}

static void
thread_free_stack(void *stack)
{
    size_t stack_size;
    char *va;

    stack_size = vm_page_round(STACK_SIZE);
    va = (char *)stack - PAGE_SIZE;

    vm_kmem_free_va(va, PAGE_SIZE);
    vm_kmem_free(va + PAGE_SIZE, stack_size);
    vm_kmem_free_va(va + PAGE_SIZE + stack_size, PAGE_SIZE);
}

#else /* X15_THREAD_STACK_GUARD */

static void *
thread_alloc_stack(void)
{
    return kmem_cache_alloc(&thread_stack_cache);
}

static void
thread_free_stack(void *stack)
{
    kmem_cache_free(&thread_stack_cache, stack);
}

#endif /* X15_THREAD_STACK_GUARD */

void
thread_destroy(struct thread *thread)
{
    struct thread_runq *runq;
    unsigned long flags, state;

    assert(thread != thread_self());

    do {
        runq = thread_lock_runq(thread, &flags);
        state = thread->state;
        thread_unlock_runq(runq, flags);
    } while (state != THREAD_DEAD);

    /* See task_info() */
    task_remove_thread(thread->task, thread);

    thread_destroy_tsd(thread);
    turnstile_destroy(thread->priv_turnstile);
    sleepq_destroy(thread->priv_sleepq);
    thread_free_stack(thread->stack);
    kmem_cache_free(&thread_cache, thread);
}

static void
thread_join_common(struct thread *thread)
{
    assert(thread != thread_self());

    mutex_lock(&thread->join_lock);

    while (!thread->exited) {
        condition_wait(&thread->join_cond, &thread->join_lock);
    }

    mutex_unlock(&thread->join_lock);

    thread_unref(thread);
}

static void
thread_reap(void *arg)
{
    struct thread_zombie *zombie;
    struct list zombies;

    (void)arg;

    for (;;) {
        mutex_lock(&thread_reap_lock);

        while (list_empty(&thread_reap_list)) {
            condition_wait(&thread_reap_cond, &thread_reap_lock);
        }

        list_set_head(&zombies, &thread_reap_list);
        list_init(&thread_reap_list);

        mutex_unlock(&thread_reap_lock);

        while (!list_empty(&zombies)) {
            zombie = list_first_entry(&zombies, struct thread_zombie, node);
            list_remove(&zombie->node);
            thread_join_common(zombie->thread);
        }
    }

    /* Never reached */
}

static void __init
thread_setup_reaper(void)
{
    struct thread_attr attr;
    struct thread *thread;
    int error;

    mutex_init(&thread_reap_lock);
    condition_init(&thread_reap_cond);
    list_init(&thread_reap_list);

    thread_attr_init(&attr, THREAD_KERNEL_PREFIX "thread_reap");
    error = thread_create(&thread, &attr, thread_reap, NULL);

    if (error) {
        panic("thread: unable to create reaper thread");
    }
}

static void
thread_balance_idle_tick(struct thread_runq *runq)
{
    assert(runq->idle_balance_ticks != 0);

    /*
     * Interrupts can occur early, at a time the balancer thread hasn't been
     * created yet.
     */
    if (runq->balancer == NULL) {
        return;
    }

    runq->idle_balance_ticks--;

    if (runq->idle_balance_ticks == 0) {
        thread_runq_wakeup_balancer(runq);
    }
}

static void
thread_balance(void *arg)
{
    struct thread_runq *runq;
    struct thread *self;
    unsigned long flags;

    runq = arg;
    self = runq->balancer;
    assert(self == runq->balancer);

    thread_preempt_disable();
    spinlock_lock_intr_save(&runq->lock, &flags);

    for (;;) {
        runq->idle_balance_ticks = THREAD_IDLE_BALANCE_TICKS;
        thread_set_wchan(self, runq, "runq");
        self->state = THREAD_SLEEPING;
        runq = thread_runq_schedule(runq);
        assert(runq == arg);

        /*
         * This function may temporarily enable preemption and release the
         * run queue lock, but on return, the lock must remain held until this
         * balancer thread sleeps.
         */
        thread_sched_fs_balance(runq, &flags);
    }
}

static void __init
thread_setup_balancer(struct thread_runq *runq)
{
    char name[THREAD_NAME_SIZE];
    struct thread_attr attr;
    struct thread *balancer;
    struct cpumap *cpumap;
    int error;

    error = cpumap_create(&cpumap);

    if (error) {
        panic("thread: unable to create balancer thread CPU map");
    }

    cpumap_zero(cpumap);
    cpumap_set(cpumap, thread_runq_cpu(runq));
    snprintf(name, sizeof(name), THREAD_KERNEL_PREFIX "thread_balance/%u",
             thread_runq_cpu(runq));
    thread_attr_init(&attr, name);
    thread_attr_set_cpumap(&attr, cpumap);
    thread_attr_set_policy(&attr, THREAD_SCHED_POLICY_FIFO);
    thread_attr_set_priority(&attr, THREAD_SCHED_RT_PRIO_MIN);
    error = thread_create(&balancer, &attr, thread_balance, runq);
    cpumap_destroy(cpumap);

    if (error) {
        panic("thread: unable to create balancer thread");
    }

    runq->balancer = balancer;
}

static void
thread_idle(void *arg)
{
    struct thread *self;
    int error;

    (void)arg;

    self = thread_self();

    for (;;) {
        thread_preempt_disable();
        error = sref_unregister();

        if (error) {
            assert(error == ERROR_BUSY);
            goto error_sref;
        }

        llsync_unregister();

        for (;;) {
            cpu_intr_disable();

            if (thread_test_flag(self, THREAD_YIELD)) {
                cpu_intr_enable();
                break;
            }

            cpu_idle();
        }

        llsync_register();
        sref_register();

error_sref:
        thread_preempt_enable();
    }
}

static void __init
thread_setup_idler(struct thread_runq *runq)
{
    char name[THREAD_NAME_SIZE];
    struct thread_attr attr;
    struct thread *idler;
    struct cpumap *cpumap;
    void *stack;
    int error;

    error = cpumap_create(&cpumap);

    if (error) {
        panic("thread: unable to allocate idler thread CPU map");
    }

    cpumap_zero(cpumap);
    cpumap_set(cpumap, thread_runq_cpu(runq));
    idler = kmem_cache_alloc(&thread_cache);

    if (idler == NULL) {
        panic("thread: unable to allocate idler thread");
    }

    stack = thread_alloc_stack();

    if (stack == NULL) {
        panic("thread: unable to allocate idler thread stack");
    }

    snprintf(name, sizeof(name), THREAD_KERNEL_PREFIX "thread_idle/%u",
             thread_runq_cpu(runq));
    thread_attr_init(&attr, name);
    thread_attr_set_cpumap(&attr, cpumap);
    thread_attr_set_policy(&attr, THREAD_SCHED_POLICY_IDLE);
    error = thread_init(idler, stack, &attr, thread_idle, NULL);

    if (error) {
        panic("thread: unable to initialize idler thread");
    }

    cpumap_destroy(cpumap);

    /* An idler thread needs special tuning */
    thread_clear_wchan(idler);
    idler->state = THREAD_RUNNING;
    idler->runq = runq;
    runq->idler = idler;
}

static void __init
thread_setup_runq(struct thread_runq *runq)
{
    thread_setup_balancer(runq);
    thread_setup_idler(runq);
}

void __init
thread_setup(void)
{
    int cpu;

    for (cpu = 1; (unsigned int)cpu < cpu_count(); cpu++) {
        thread_bootstrap_common(cpu);
    }

    kmem_cache_init(&thread_cache, "thread", sizeof(struct thread),
                    CPU_L1_SIZE, NULL, 0);
#ifndef X15_THREAD_STACK_GUARD
    kmem_cache_init(&thread_stack_cache, "thread_stack", STACK_SIZE,
                    DATA_ALIGN, NULL, 0);
#endif /* X15_THREAD_STACK_GUARD */

    thread_setup_reaper();

    cpumap_for_each(&thread_active_runqs, cpu) {
        thread_setup_runq(percpu_ptr(thread_runq, cpu));
    }
}

int
thread_create(struct thread **threadp, const struct thread_attr *attr,
              void (*fn)(void *), void *arg)

{
    struct thread *thread;
    void *stack;
    int error;

    if (attr->cpumap != NULL) {
        error = cpumap_check(attr->cpumap);

        if (error) {
            return error;
        }
    }

    thread = kmem_cache_alloc(&thread_cache);

    if (thread == NULL) {
        error = ERROR_NOMEM;
        goto error_thread;
    }

    stack = thread_alloc_stack();

    if (stack == NULL) {
        error = ERROR_NOMEM;
        goto error_stack;
    }

    error = thread_init(thread, stack, attr, fn, arg);

    if (error) {
        goto error_init;
    }

    /*
     * The new thread address must be written before the thread is started
     * in case it's passed to it.
     */
    *threadp = thread;

    thread_wakeup(thread);

    return 0;

error_init:
    thread_free_stack(stack);
error_stack:
    kmem_cache_free(&thread_cache, thread);
error_thread:
    return error;
}

void
thread_exit(void)
{
    struct thread_zombie zombie;
    struct thread_runq *runq;
    struct thread *thread;
    unsigned long flags;

    thread = thread_self();

    if (thread_test_flag(thread, THREAD_DETACHED)) {
        zombie.thread = thread;

        mutex_lock(&thread_reap_lock);
        list_insert_tail(&thread_reap_list, &zombie.node);
        condition_signal(&thread_reap_cond);
        mutex_unlock(&thread_reap_lock);
    }

    mutex_lock(&thread->join_lock);
    thread->exited = 1;
    condition_signal(&thread->join_cond);

    /*
     * Disable preemption before releasing the mutex to make sure the current
     * thread becomes dead as soon as possible. This is important because the
     * joining thread actively polls the thread state before destroying it.
     */
    thread_preempt_disable();

    mutex_unlock(&thread->join_lock);

    runq = thread_runq_local();
    spinlock_lock_intr_save(&runq->lock, &flags);

    thread->state = THREAD_DEAD;

    thread_runq_schedule(runq);
    panic("thread: dead thread walking");
}

void
thread_join(struct thread *thread)
{
    assert(!thread_test_flag(thread, THREAD_DETACHED));
    thread_join_common(thread);
}

void
thread_sleep(struct spinlock *interlock, const void *wchan_addr,
             const char *wchan_desc)
{
    struct thread_runq *runq;
    struct thread *thread;
    unsigned long flags;

    thread = thread_self();
    assert(thread->preempt == 1);

    runq = thread_runq_local();
    spinlock_lock_intr_save(&runq->lock, &flags);

    if (interlock != NULL) {
        thread_preempt_disable();
        spinlock_unlock(interlock);
    }

    thread_set_wchan(thread, wchan_addr, wchan_desc);
    thread->state = THREAD_SLEEPING;

    runq = thread_runq_schedule(runq);
    assert(thread->state == THREAD_RUNNING);

    spinlock_unlock_intr_restore(&runq->lock, flags);

    if (interlock != NULL) {
        spinlock_lock(interlock);
        thread_preempt_enable_no_resched();
    }

    assert(thread->preempt == 1);
}

void
thread_wakeup(struct thread *thread)
{
    struct thread_runq *runq;
    unsigned long flags;

    /*
     * There is at most one reference on threads that were never dispatched,
     * in which case there is no need to lock anything.
     */
    if (thread->runq == NULL) {
        assert(thread->state != THREAD_RUNNING);
        thread_clear_wchan(thread);
        thread->state = THREAD_RUNNING;
    } else {
        runq = thread_lock_runq(thread, &flags);

        if (thread->state == THREAD_RUNNING) {
            thread_unlock_runq(runq, flags);
            return;
        }

        thread_clear_wchan(thread);
        thread->state = THREAD_RUNNING;
        thread_unlock_runq(runq, flags);
    }

    thread_preempt_disable();
    cpu_intr_save(&flags);

    if (!thread->pinned) {
        runq = thread_get_real_sched_ops(thread)->select_runq(thread);
    } else {
        runq = thread->runq;
        spinlock_lock(&runq->lock);
    }

    thread_runq_wakeup(runq, thread);
    spinlock_unlock(&runq->lock);
    cpu_intr_restore(flags);
    thread_preempt_enable();
}

void __init
thread_run_scheduler(void)
{
    struct thread_runq *runq;
    struct thread *thread;

    assert(!cpu_intr_enabled());

    runq = thread_runq_local();
    thread = thread_self();
    assert(thread == runq->current);
    assert(thread->preempt == 1);

    llsync_register();
    sref_register();

    spinlock_lock(&runq->lock);
    thread = thread_runq_get_next(thread_runq_local());

    tcb_load(&thread->tcb);
}

void
thread_yield(void)
{
    struct thread_runq *runq;
    struct thread *thread;
    unsigned long flags;

    thread = thread_self();

    if (!thread_preempt_enabled()) {
        return;
    }

    do {
        thread_preempt_disable();
        runq = thread_runq_local();
        spinlock_lock_intr_save(&runq->lock, &flags);
        runq = thread_runq_schedule(runq);
        spinlock_unlock_intr_restore(&runq->lock, flags);
        thread_preempt_enable_no_resched();
    } while (thread_test_flag(thread, THREAD_YIELD));
}

void
thread_schedule(void)
{
    if (likely(!thread_test_flag(thread_self(), THREAD_YIELD))) {
        return;
    }

    thread_yield();
}

void
thread_schedule_intr(void)
{
    struct thread_runq *runq;

    thread_assert_interrupted();

    runq = thread_runq_local();
    syscnt_inc(&runq->sc_schedule_intrs);
}

void
thread_tick_intr(void)
{
    const struct thread_sched_ops *ops;
    struct thread_runq *runq;
    struct thread *thread;

    thread_assert_interrupted();

    runq = thread_runq_local();
    syscnt_inc(&runq->sc_tick_intrs);
    llsync_report_periodic_event();
    sref_report_periodic_event();
    work_report_periodic_event();
    thread = thread_self();

    spinlock_lock(&runq->lock);

    if (runq->nr_threads == 0) {
        thread_balance_idle_tick(runq);
    }

    ops = thread_get_real_sched_ops(thread);

    if (ops->tick != NULL) {
        ops->tick(runq, thread);
    }

    spinlock_unlock(&runq->lock);
}

char
thread_state_to_chr(const struct thread *thread)
{
    switch (thread->state) {
    case THREAD_RUNNING:
        return 'R';
    case THREAD_SLEEPING:
        return 'S';
    case THREAD_DEAD:
        return 'Z';
    default:
        panic("thread: unknown state");
    }
}

const char *
thread_sched_class_to_str(unsigned char sched_class)
{
    switch (sched_class) {
    case THREAD_SCHED_CLASS_RT:
        return "rt";
    case THREAD_SCHED_CLASS_FS:
        return "fs";
    case THREAD_SCHED_CLASS_IDLE:
        return "idle";
    default:
        panic("thread: unknown scheduling class");
    }
}

void
thread_setscheduler(struct thread *thread, unsigned char policy,
                    unsigned short priority)
{
    struct thread_runq *runq;
    struct turnstile_td *td;
    unsigned long flags;
    bool requeue, current, update;

    td = thread_turnstile_td(thread);

    turnstile_td_lock(td);
    runq = thread_lock_runq(thread, &flags);

    if ((thread_user_sched_policy(thread) == policy)
        && (thread_user_priority(thread) == priority)) {
        goto out;
    }

    requeue = thread->in_runq;

    if (!requeue) {
        current = false;
    } else {
        if (thread != runq->current) {
            current = false;
        } else {
            thread_runq_put_prev(runq, thread);
            current = true;
        }

        thread_runq_remove(runq, thread);
    }

    if (thread_user_sched_policy(thread) == policy) {
        thread_update_user_priority(thread, priority);
        update = true;
    } else {
        thread_set_user_sched_policy(thread, policy);
        thread_set_user_sched_class(thread, thread_policy_to_class(policy));
        thread_set_user_priority(thread, priority);
        update = false;
    }

    if (thread->boosted) {
        if (thread_user_global_priority(thread)
            >= thread_real_global_priority(thread)) {
            thread_reset_real_priority(thread);
        }
    } else {
        if (update) {
            thread_update_real_priority(thread, priority);
        } else {
            thread_set_real_sched_policy(thread, policy);
            thread_set_real_sched_class(thread, thread_policy_to_class(policy));
            thread_set_real_priority(thread, priority);
        }
    }

    if (requeue) {
        thread_runq_add(runq, thread);

        if (current) {
            thread_runq_set_next(runq, thread);
        }
    }

out:
    thread_unlock_runq(runq, flags);
    turnstile_td_unlock(td);

    turnstile_td_propagate_priority(td);
}

void
thread_pi_setscheduler(struct thread *thread, unsigned char policy,
                       unsigned short priority)
{
    const struct thread_sched_ops *ops;
    struct thread_runq *runq;
    struct turnstile_td *td;
    unsigned int global_priority;
    unsigned long flags;
    bool requeue, current;

    td = thread_turnstile_td(thread);
    turnstile_td_assert_lock(td);

    ops = thread_get_sched_ops(thread_policy_to_class(policy));
    global_priority = ops->get_global_priority(priority);

    runq = thread_lock_runq(thread, &flags);

    if ((thread_real_sched_policy(thread) == policy)
        && (thread_real_priority(thread) == priority)) {
        goto out;
    }

    syscnt_inc(&runq->sc_boosts);

    requeue = thread->in_runq;

    if (!requeue) {
        current = false;
    } else {
        if (thread != runq->current) {
            current = false;
        } else {
            thread_runq_put_prev(runq, thread);
            current = true;
        }

        thread_runq_remove(runq, thread);
    }

    if (global_priority <= thread_user_global_priority(thread)) {
        thread_reset_real_priority(thread);
    } else {
        if (thread_real_sched_policy(thread) == policy) {
            thread_update_real_priority(thread, priority);
        } else {
            thread_set_real_sched_policy(thread, policy);
            thread_set_real_sched_class(thread, thread_policy_to_class(policy));
            thread_set_real_priority(thread, priority);
        }

        thread->boosted = true;
    }

    if (requeue) {
        thread_runq_add(runq, thread);

        if (current) {
            thread_runq_set_next(runq, thread);
        }
    }

out:
    thread_unlock_runq(runq, flags);
}

void
thread_propagate_priority(void)
{
    struct thread *thread;

    /*
     * Although it's possible to propagate priority with preemption
     * disabled, the operation can be too expensive to allow it.
     */
    if (!thread_preempt_enabled()) {
        thread_set_priority_propagation_needed();
        return;
    }

    thread = thread_self();

    /* Clear before propagation to avoid infinite recursion */
    thread->propagate_priority = false;

    turnstile_td_propagate_priority(thread_turnstile_td(thread));
}

void
thread_key_create(unsigned int *keyp, thread_dtor_fn_t dtor)
{
    unsigned int key;

    key = atomic_fetch_add(&thread_nr_keys, 1, ATOMIC_RELAXED);

    if (key >= THREAD_KEYS_MAX) {
        panic("thread: maximum number of keys exceeded");
    }

    thread_dtors[key] = dtor;
    *keyp = key;
}
