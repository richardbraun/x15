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
 *
 *
 * By convention, the name of a kernel thread is built by prefixing the
 * kernel name and adding the name of the start function, without the module
 * name ("thread"). Threads that are bound to a processor also include the
 * "/cpu_id" suffix. For example, "x15_balancer/1" is the name of the
 * inter-processor balancing thread of the second processor.
 */

#include <kern/assert.h>
#include <kern/bitmap.h>
#include <kern/error.h>
#include <kern/init.h>
#include <kern/kmem.h>
#include <kern/list.h>
#include <kern/macros.h>
#include <kern/panic.h>
#include <kern/param.h>
#include <kern/printk.h>
#include <kern/spinlock.h>
#include <kern/sprintf.h>
#include <kern/stddef.h>
#include <kern/string.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <machine/atomic.h>
#include <machine/cpu.h>
#include <machine/mb.h>
#include <machine/pmap.h>
#include <machine/tcb.h>
#include <vm/vm_map.h>

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
#define THREAD_TS_INITIAL_ROUND ((unsigned long)-10)

/*
 * When pulling threads from a run queue, this value is used to determine
 * the total number of threads to pull by dividing the number of eligible
 * threads with it.
 */
#define THREAD_TS_MIGRATION_RATIO 2

/*
 * Group of threads sharing the same weight.
 */
struct thread_ts_group {
    struct list node;
    struct list threads;
    unsigned int weight;
    unsigned int work;
};

/*
 * Run queue properties for time-sharing threads.
 *
 * The current group pointer has a valid address only when the run queue isn't
 * empty.
 */
struct thread_ts_runq {
    struct thread_ts_group group_array[THREAD_SCHED_TS_PRIO_MAX + 1];
    struct list groups;
    struct list threads;
    struct thread_ts_group *current;
    unsigned int nr_threads;
    unsigned int weight;
    unsigned int work;
};

/*
 * Per processor run queue.
 *
 * Locking multiple run queues is done in the ascending order of their
 * addresses.
 */
struct thread_runq {
    struct spinlock lock;
    struct thread *current;
    unsigned int nr_threads;

    /* Real-time related members */
    struct thread_rt_runq rt_runq;

    /*
     * Time-sharing related members.
     *
     * The current round is set when the active run queue becomes non-empty.
     * It's not reset when both run queues become empty. As a result, the
     * current round has a meaningful value only when at least one thread is
     * present, i.e. the global weight isn't zero.
     */
    unsigned long ts_round;
    unsigned int ts_weight;
    struct thread_ts_runq ts_runqs[2];
    struct thread_ts_runq *ts_runq_active;
    struct thread_ts_runq *ts_runq_expired;

    struct thread *idler;
    struct thread *balancer;
} __aligned(CPU_L1_SIZE);

/*
 * Operations of a scheduling class.
 */
struct thread_sched_ops {
    void (*init_thread)(struct thread *thread, unsigned short priority);
    struct thread_runq * (*select_runq)(void);
    void (*add)(struct thread_runq *runq, struct thread *thread);
    void (*remove)(struct thread_runq *runq, struct thread *thread);
    void (*put_prev)(struct thread_runq *runq, struct thread *thread);
    struct thread * (*get_next)(struct thread_runq *runq);
    void (*tick)(struct thread_runq *runq, struct thread *thread);
};

static struct thread_runq thread_runqs[MAX_CPUS];

/*
 * Statically allocating the idler thread structures enables their use as
 * "current" threads during system bootstrap, which prevents migration and
 * preemption control functions from crashing.
 */
static struct thread thread_idlers[MAX_CPUS];

/*
 * Caches for allocated threads and their stacks.
 */
static struct kmem_cache thread_cache;
static struct kmem_cache thread_stack_cache;

/*
 * Table used to quickly map policies to classes.
 */
static unsigned char thread_policy_table[THREAD_NR_SCHED_POLICIES];

/*
 * Scheduling class operations.
 */
static struct thread_sched_ops thread_sched_ops[THREAD_NR_SCHED_CLASSES];

static struct thread_attr thread_default_attr = {
    NULL,
    NULL,
    THREAD_SCHED_POLICY_TS,
    THREAD_SCHED_TS_PRIO_DEFAULT
};

BITMAP_DECLARE(thread_active_runqs, MAX_CPUS);

/*
 * System-wide value of the current highest round.
 *
 * There can be moderate bouncing on this word so give it its own cache line.
 */
static struct {
    volatile unsigned long value __aligned(CPU_L1_SIZE);
} thread_ts_highest_round_struct;

#define thread_ts_highest_round (thread_ts_highest_round_struct.value)

static void __init
thread_runq_init_rt(struct thread_runq *runq)
{
    struct thread_rt_runq *rt_runq;
    size_t i;

    rt_runq = &runq->rt_runq;
    rt_runq->bitmap = 0;

    for (i = 0; i < ARRAY_SIZE(rt_runq->threads); i++)
        list_init(&rt_runq->threads[i]);
}

static void __init
thread_ts_group_init(struct thread_ts_group *group)
{
    list_init(&group->threads);
    group->weight = 0;
    group->work = 0;
}

static void __init
thread_ts_runq_init(struct thread_ts_runq *ts_runq)
{
    size_t i;

    for (i = 0; i < ARRAY_SIZE(ts_runq->group_array); i++)
        thread_ts_group_init(&ts_runq->group_array[i]);

    list_init(&ts_runq->groups);
    list_init(&ts_runq->threads);
    ts_runq->nr_threads = 0;
    ts_runq->weight = 0;
    ts_runq->work = 0;
}

static void __init
thread_runq_init_ts(struct thread_runq *runq)
{
    runq->ts_weight = 0;
    runq->ts_runq_active = &runq->ts_runqs[0];
    runq->ts_runq_expired = &runq->ts_runqs[1];
    thread_ts_runq_init(runq->ts_runq_active);
    thread_ts_runq_init(runq->ts_runq_expired);
}

static void __init
thread_runq_init_idle(struct thread_runq *runq)
{
    struct thread *idler;

    /* Initialize what's needed during bootstrap */
    idler = &thread_idlers[runq - thread_runqs];
    idler->flags = 0;
    idler->preempt = 1;
    idler->sched_policy = THREAD_SCHED_POLICY_IDLE;
    idler->sched_class = THREAD_SCHED_CLASS_IDLE;
    idler->task = kernel_task;
    runq->idler = idler;
}

static void __init
thread_runq_init(struct thread_runq *runq)
{
    spinlock_init(&runq->lock);
    runq->nr_threads = 0;
    thread_runq_init_rt(runq);
    thread_runq_init_ts(runq);
    thread_runq_init_idle(runq);
    runq->current = runq->idler;
    runq->balancer = NULL;
}

static inline int
thread_runq_id(struct thread_runq *runq)
{
    return runq - thread_runqs;
}

static inline struct thread_runq *
thread_runq_local(void)
{
    assert(!thread_preempt_enabled() || thread_pinned());
    return &thread_runqs[cpu_id()];
}

static inline void
thread_set_flag(struct thread *thread, unsigned long flag)
{
    atomic_or(&thread->flags, flag);
}

static inline void
thread_clear_flag(struct thread *thread, unsigned long flag)
{
    atomic_and(&thread->flags, ~flag);
}

static inline int
thread_test_flag(struct thread *thread, unsigned long flag)
{
    barrier();
    return ((thread->flags & flag) != 0);
}

static void
thread_runq_add(struct thread_runq *runq, struct thread *thread)
{
    spinlock_assert_locked(&runq->lock);

    thread_sched_ops[thread->sched_class].add(runq, thread);

    if (runq->nr_threads == 0)
        bitmap_set_atomic(thread_active_runqs, thread_runq_id(runq));

    runq->nr_threads++;

    if (thread->sched_class < runq->current->sched_class)
        thread_set_flag(runq->current, THREAD_RESCHEDULE);
}

static void
thread_runq_remove(struct thread_runq *runq, struct thread *thread)
{
    spinlock_assert_locked(&runq->lock);

    runq->nr_threads--;

    if (runq->nr_threads == 0)
        bitmap_clear_atomic(thread_active_runqs, thread_runq_id(runq));

    thread_sched_ops[thread->sched_class].remove(runq, thread);
}

static void
thread_runq_put_prev(struct thread_runq *runq, struct thread *thread)
{
    assert(!cpu_intr_enabled());
    spinlock_assert_locked(&runq->lock);

    thread_sched_ops[thread->sched_class].put_prev(runq, thread);
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
thread_runq_wakeup(struct thread_runq *runq, struct thread *thread)
{
    spinlock_assert_locked(&runq->lock);
    assert(thread->on_rq);

    thread->state = THREAD_RUNNING;
    thread_runq_add(runq, thread);

    if (runq != thread_runq_local()) {
        /*
         * Make the new state and flags globally visible so that a remote
         * rescheduling operation sees the correct values.
         *
         * Although scheduling implies a load memory barrier before testing
         * the state of a thread (because of the spin lock acquire semantics),
         * this isn't the case with thread flags. They are set atomically,
         * but not ordered. As a result, reenabling preemption may miss a
         * rescheduling request. But interrupts imply full memory barriers
         * so the request won't be missed when the rescheduling IPI is
         * received by the remote processor.
         */
        mb_store();

        if (thread_test_flag(runq->current, THREAD_RESCHEDULE))
            tcb_send_reschedule(thread_runq_id(runq));
    }
}

static void
thread_runq_double_lock(struct thread_runq *a, struct thread_runq *b)
{
    assert(a != b);

    if (a < b) {
        spinlock_lock(&a->lock);
        spinlock_lock(&b->lock);
    } else {
        spinlock_lock(&b->lock);
        spinlock_lock(&a->lock);
    }
}

static void
thread_sched_rt_init_thread(struct thread *thread, unsigned short priority)
{
    assert(priority <= THREAD_SCHED_RT_PRIO_MAX);
    thread->rt_ctx.priority = priority;
    thread->rt_ctx.time_slice = THREAD_DEFAULT_RR_TIME_SLICE;
}

static struct thread_runq *
thread_sched_rt_select_runq(void)
{
    struct thread_runq *runq;

    runq = thread_runq_local();
    spinlock_lock(&runq->lock);
    return runq;
}

static void
thread_sched_rt_add(struct thread_runq *runq, struct thread *thread)
{
    struct thread_rt_runq *rt_runq;
    struct list *threads;

    rt_runq = &runq->rt_runq;
    threads = &rt_runq->threads[thread->rt_ctx.priority];
    list_insert_tail(threads, &thread->rt_ctx.node);

    if (list_singular(threads))
        rt_runq->bitmap |= (1U << thread->rt_ctx.priority);

    if ((thread->sched_class == runq->current->sched_class)
        && (thread->rt_ctx.priority > runq->current->rt_ctx.priority))
        thread_set_flag(runq->current, THREAD_RESCHEDULE);
}

static void
thread_sched_rt_remove(struct thread_runq *runq, struct thread *thread)
{
    struct thread_rt_runq *rt_runq;
    struct list *threads;

    rt_runq = &runq->rt_runq;
    threads = &rt_runq->threads[thread->rt_ctx.priority];
    list_remove(&thread->rt_ctx.node);

    if (list_empty(threads))
        rt_runq->bitmap &= ~(1U << thread->rt_ctx.priority);
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

    if (rt_runq->bitmap == 0)
        return NULL;

    priority = THREAD_SCHED_RT_PRIO_MAX - __builtin_clz(rt_runq->bitmap);
    threads = &rt_runq->threads[priority];
    assert(!list_empty(threads));
    thread = list_first_entry(threads, struct thread, rt_ctx.node);
    thread_sched_rt_remove(runq, thread);
    return thread;
}

static void
thread_sched_rt_tick(struct thread_runq *runq, struct thread *thread)
{
    (void)runq;

    if (thread->sched_policy != THREAD_SCHED_POLICY_RR)
        return;

    thread->rt_ctx.time_slice--;

    if (thread->rt_ctx.time_slice > 0)
        return;

    thread->rt_ctx.time_slice = THREAD_DEFAULT_RR_TIME_SLICE;
    thread_set_flag(thread, THREAD_RESCHEDULE);
}

static void
thread_sched_ts_init_thread(struct thread *thread, unsigned short priority)
{
    assert(priority <= THREAD_SCHED_TS_PRIO_MAX);
    thread->ts_ctx.ts_runq = NULL;
    thread->ts_ctx.round = 0;
    thread->ts_ctx.weight = priority + 1;
    thread->ts_ctx.work = 0;
}

static struct thread_runq *
thread_sched_ts_select_runq(void)
{
    struct thread_runq *runq, *tmp;
    int i, nr_runqs;
    long delta;

    nr_runqs = cpu_count();

    bitmap_for_each_zero(thread_active_runqs, nr_runqs, i) {
        runq = &thread_runqs[i];

        spinlock_lock(&runq->lock);

        /* The run queue really is idle, return it */
        if (runq->current == runq->idler)
            goto out;

        spinlock_unlock(&runq->lock);
    }

    runq = &thread_runqs[0];

    spinlock_lock(&runq->lock);

    for (i = 1; i < nr_runqs; i++) {
        tmp = &thread_runqs[i];

        spinlock_lock(&tmp->lock);

        /* A run queue may have become idle */
        if (tmp->current == tmp->idler) {
            spinlock_unlock(&runq->lock);
            runq = tmp;
            goto out;
        }

        /*
         * The run queue isn't idle, but there are no time-sharing thread,
         * which means there are real-time threads.
         */
        if (tmp->ts_weight == 0) {
            spinlock_unlock(&tmp->lock);
            continue;
        }

        delta = (long)(tmp->ts_round - runq->ts_round);

        /* Look for the least loaded of the run queues in the highest round */
        if ((delta > 0)
            || ((delta == 0) && (tmp->ts_weight < runq->ts_weight))) {
            spinlock_unlock(&runq->lock);
            runq = tmp;
            continue;
        }

        spinlock_unlock(&tmp->lock);
    }

out:
    return runq;
}

static unsigned int
thread_sched_ts_enqueue_scale(unsigned int work, unsigned int old_weight,
                              unsigned int new_weight)
{
    assert(old_weight != 0);

#ifndef __LP64__
    if (likely((work < 0x10000) && (new_weight < 0x10000)))
        return (work * new_weight) / old_weight;
#endif /* __LP64__ */

    return (unsigned int)(((unsigned long long)work * new_weight) / old_weight);
}

static void
thread_sched_ts_enqueue(struct thread_ts_runq *ts_runq, unsigned long round,
                        struct thread *thread)
{
    struct thread_ts_group *group, *tmp;
    struct list *node, *init_node;
    unsigned int group_weight, total_weight;

    assert(thread->ts_ctx.ts_runq == NULL);

    group = &ts_runq->group_array[thread->ts_ctx.weight - 1];
    group_weight = group->weight + thread->ts_ctx.weight;
    total_weight = ts_runq->weight + thread->ts_ctx.weight;
    node = (group->weight == 0)
           ? list_last(&ts_runq->groups)
           : list_prev(&group->node);
    init_node = node;

    while (!list_end(&ts_runq->groups, node)) {
        tmp = list_entry(node, struct thread_ts_group, node);

        if (tmp->weight >= group_weight)
            break;

        node = list_prev(node);
    }

    if (group->weight == 0)
        list_insert_after(node, &group->node);
    else if (node != init_node) {
        list_remove(&group->node);
        list_insert_after(node, &group->node);
    }

    /*
     * XXX Unfairness can occur if the run queue round wraps around and the
     * thread is "lucky" enough to have the same round value. This should be
     * rare and harmless otherwise.
     */
    if (thread->ts_ctx.round == round) {
        ts_runq->work += thread->ts_ctx.work;
        group->work += thread->ts_ctx.work;
    } else {
        unsigned int group_work, thread_work;

        if (ts_runq->weight == 0)
            thread_work = 0;
        else {
            group_work = (group->weight == 0)
                         ? thread_sched_ts_enqueue_scale(ts_runq->work,
                                                         ts_runq->weight,
                                                         thread->ts_ctx.weight)
                         : thread_sched_ts_enqueue_scale(group->work,
                                                         group->weight,
                                                         group_weight);
            thread_work = group_work - group->work;
            ts_runq->work += thread_work;
            group->work = group_work;
        }

        thread->ts_ctx.round = round;
        thread->ts_ctx.work = thread_work;
    }

    ts_runq->nr_threads++;
    ts_runq->weight = total_weight;
    group->weight = group_weight;

    /* Insert at the front of the group to improve interactivity */
    list_insert(&group->threads, &thread->ts_ctx.group_node);
    list_insert_tail(&ts_runq->threads, &thread->ts_ctx.runq_node);
    thread->ts_ctx.ts_runq = ts_runq;
}

static void
thread_sched_ts_restart(struct thread_runq *runq)
{
    struct thread_ts_runq *ts_runq;
    struct list *node;

    ts_runq = runq->ts_runq_active;
    node = list_first(&ts_runq->groups);
    assert(node != NULL);
    ts_runq->current = list_entry(node, struct thread_ts_group, node);

    if (runq->current->sched_class == THREAD_SCHED_CLASS_TS)
        thread_set_flag(runq->current, THREAD_RESCHEDULE);
}

static void
thread_sched_ts_add(struct thread_runq *runq, struct thread *thread)
{
    unsigned int total_weight;

    if (runq->ts_weight == 0)
        runq->ts_round = thread_ts_highest_round;

    total_weight = runq->ts_weight + thread->ts_ctx.weight;

    /* TODO Limit the maximum number of threads to prevent this situation */
    if (total_weight < runq->ts_weight)
        panic("thread: weight overflow");

    runq->ts_weight = total_weight;
    thread_sched_ts_enqueue(runq->ts_runq_active, runq->ts_round, thread);
    thread_sched_ts_restart(runq);
}

static void
thread_sched_ts_dequeue(struct thread *thread)
{
    struct thread_ts_runq *ts_runq;
    struct thread_ts_group *group, *tmp;
    struct list *node, *init_node;

    assert(thread->ts_ctx.ts_runq != NULL);

    ts_runq = thread->ts_ctx.ts_runq;
    group = &ts_runq->group_array[thread->ts_ctx.weight - 1];

    thread->ts_ctx.ts_runq = NULL;
    list_remove(&thread->ts_ctx.runq_node);
    list_remove(&thread->ts_ctx.group_node);
    ts_runq->work -= thread->ts_ctx.work;
    group->work -= thread->ts_ctx.work;
    ts_runq->weight -= thread->ts_ctx.weight;
    group->weight -= thread->ts_ctx.weight;
    ts_runq->nr_threads--;

    if (group->weight == 0)
        list_remove(&group->node);
    else {
        node = list_next(&group->node);
        init_node = node;

        while (!list_end(&ts_runq->groups, node)) {
            tmp = list_entry(node, struct thread_ts_group, node);

            if (tmp->weight <= group->weight)
                break;

            node = list_next(node);
        }

        if (node != init_node) {
            list_remove(&group->node);
            list_insert_before(node, &group->node);
        }
    }
}

static void
thread_sched_ts_wakeup_balancer(struct thread_runq *runq)
{
    unsigned long on_rq;

    on_rq = atomic_cas(&runq->balancer->on_rq, 0, 1);

    if (on_rq)
        return;

    thread_runq_wakeup(runq, runq->balancer);
}

static void
thread_sched_ts_remove(struct thread_runq *runq, struct thread *thread)
{
    struct thread_ts_runq *ts_runq;

    runq->ts_weight -= thread->ts_ctx.weight;
    ts_runq = thread->ts_ctx.ts_runq;
    thread_sched_ts_dequeue(thread);

    if (ts_runq == runq->ts_runq_active) {
        if (ts_runq->nr_threads == 0)
            thread_sched_ts_wakeup_balancer(runq);
        else
            thread_sched_ts_restart(runq);
    }
}

static void
thread_sched_ts_deactivate(struct thread_runq *runq, struct thread *thread)
{
    assert(thread->ts_ctx.ts_runq == runq->ts_runq_active);
    assert(thread->ts_ctx.round == runq->ts_round);

    thread_sched_ts_dequeue(thread);
    thread->ts_ctx.round++;
    thread->ts_ctx.work -= thread->ts_ctx.weight;
    thread_sched_ts_enqueue(runq->ts_runq_expired, runq->ts_round + 1, thread);

    if (runq->ts_runq_active->nr_threads == 0)
        thread_sched_ts_wakeup_balancer(runq);
}

static void
thread_sched_ts_put_prev(struct thread_runq *runq, struct thread *thread)
{
    struct thread_ts_runq *ts_runq;
    struct thread_ts_group *group;

    ts_runq = runq->ts_runq_active;
    group = &ts_runq->group_array[thread->ts_ctx.weight - 1];
    list_insert_tail(&group->threads, &thread->ts_ctx.group_node);

    if (thread->ts_ctx.work >= thread->ts_ctx.weight)
        thread_sched_ts_deactivate(runq, thread);
}

static int
thread_sched_ts_ratio_exceeded(struct thread_ts_group *current,
                               struct thread_ts_group *next)
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
thread_sched_ts_get_next(struct thread_runq *runq)
{
    struct thread_ts_runq *ts_runq;
    struct thread_ts_group *group, *next;
    struct thread *thread;
    struct list *node;

    ts_runq = runq->ts_runq_active;

    if (ts_runq->nr_threads == 0)
        return NULL;

    group = ts_runq->current;
    node = list_next(&group->node);

    if (list_end(&ts_runq->groups, node)) {
        node = list_first(&ts_runq->groups);
        group = list_entry(node, struct thread_ts_group, node);
    } else {
        next = list_entry(node, struct thread_ts_group, node);

        if (thread_sched_ts_ratio_exceeded(group, next))
            group = next;
        else {
            node = list_first(&ts_runq->groups);
            group = list_entry(node, struct thread_ts_group, node);
        }
    }

    ts_runq->current = group;
    node = list_first(&group->threads);
    thread = list_entry(node, struct thread, ts_ctx.group_node);
    list_remove(node);
    return thread;
}

static void
thread_sched_ts_tick(struct thread_runq *runq, struct thread *thread)
{
    struct thread_ts_runq *ts_runq;
    struct thread_ts_group *group;

    ts_runq = runq->ts_runq_active;
    ts_runq->work++;
    group = &ts_runq->group_array[thread->ts_ctx.weight - 1];
    group->work++;
    thread_set_flag(thread, THREAD_RESCHEDULE);
    thread->ts_ctx.work++;
}

static void
thread_sched_ts_start_next_round(struct thread_runq *runq)
{
    struct thread_ts_runq *tmp;
    long delta;

    tmp = runq->ts_runq_expired;
    runq->ts_runq_expired = runq->ts_runq_active;
    runq->ts_runq_active = tmp;

    if (runq->ts_runq_active->nr_threads != 0) {
        runq->ts_round++;
        delta = (long)(runq->ts_round - thread_ts_highest_round);

        if (delta > 0)
            thread_ts_highest_round = runq->ts_round;

        thread_sched_ts_restart(runq);
    }
}

static int
thread_sched_ts_balance_eligible(struct thread_runq *runq)
{
    unsigned long highest_round;
    unsigned int nr_threads;

    if (runq->current == runq->idler)
        return 0;

    highest_round = thread_ts_highest_round;

    if (runq->ts_weight == 0)
        return 0;

    if ((runq->ts_round != highest_round)
        && (runq->ts_round != (highest_round - 1)))
        return 0;

    nr_threads = runq->ts_runq_active->nr_threads;

    if (runq->ts_round != highest_round)
        nr_threads += runq->ts_runq_expired->nr_threads;

    assert(nr_threads != 0);

    if ((nr_threads == 1)
        && (runq->current->sched_class == THREAD_SCHED_CLASS_TS))
        return 0;

    return 1;
}

/*
 * Try to find the most suitable run queue from which to pull threads.
 */
static struct thread_runq *
thread_sched_ts_balance_scan(struct thread_runq *runq)
{
    struct thread_runq *remote_runq;
    unsigned int highest_weight;
    int i, runq_id, nr_runqs, eligible;

    runq_id = -1;
    nr_runqs = cpu_count();
    highest_weight = 0;

    bitmap_for_each(thread_active_runqs, nr_runqs, i) {
        remote_runq = &thread_runqs[i];

        if (remote_runq == runq)
            continue;

        spinlock_lock(&thread_runqs[i].lock);

        eligible = thread_sched_ts_balance_eligible(&thread_runqs[i]);

        if (!eligible) {
            spinlock_unlock(&thread_runqs[i].lock);
            continue;
        }

        if (remote_runq->ts_weight > highest_weight) {
            highest_weight = remote_runq->ts_weight;
            runq_id = i;
        }

        spinlock_unlock(&thread_runqs[i].lock);
    }

    if (runq_id == -1)
        return NULL;

    return &thread_runqs[runq_id];
}

static unsigned int
thread_sched_ts_balance_migrate(struct thread_runq *runq,
                                struct thread_runq *remote_runq)
{
    struct thread *thread, *tmp;
    unsigned long flags;
    unsigned int i, nr_threads;
    int not_highest;

    thread_preempt_disable();
    flags = cpu_intr_save();
    thread_runq_double_lock(runq, remote_runq);

    if (!thread_sched_ts_balance_eligible(remote_runq)) {
        i = 0;
        goto out;
    }

    nr_threads = remote_runq->ts_runq_active->nr_threads;

    if (remote_runq->ts_round == thread_ts_highest_round)
        not_highest = 0;
    else {
        not_highest = 1;
        nr_threads += remote_runq->ts_runq_expired->nr_threads;
    }

    i = 0;
    nr_threads = nr_threads / THREAD_TS_MIGRATION_RATIO;

    if (nr_threads == 0)
        nr_threads = 1;
    else if (nr_threads > THREAD_MAX_MIGRATIONS)
        nr_threads = THREAD_MAX_MIGRATIONS;

    list_for_each_entry_safe(&remote_runq->ts_runq_active->threads,
                             thread, tmp, ts_ctx.runq_node) {
        if (thread == remote_runq->current)
            continue;

        thread_runq_remove(remote_runq, thread);
        thread->ts_ctx.round = runq->ts_round;
        thread_runq_add(runq, thread);
        i++;

        if (i == nr_threads)
            goto out;
    }

    if (not_highest)
        list_for_each_entry_safe(&remote_runq->ts_runq_expired->threads,
                                 thread, tmp, ts_ctx.runq_node) {
            thread_runq_remove(remote_runq, thread);
            thread->ts_ctx.round = runq->ts_round;
            thread_runq_add(runq, thread);
            i++;

            if (i == nr_threads)
                goto out;
        }

out:
    spinlock_unlock(&runq->lock);
    spinlock_unlock(&remote_runq->lock);
    cpu_intr_restore(flags);
    thread_preempt_enable();
    return i;
}

static void
thread_sched_ts_balance(struct thread_runq *runq)
{
    struct thread_runq *remote_runq;
    unsigned long flags;
    unsigned int nr_migrations;
    int i, nr_runqs;

    /*
     * These values can't change while the balancer thread is running, so
     * don't bother locking.
     */
    if ((runq->ts_round == thread_ts_highest_round)
        || (runq->ts_runq_expired->nr_threads == 0))
        remote_runq = thread_sched_ts_balance_scan(runq);
    else
        remote_runq = NULL;

    if (remote_runq == NULL)
        goto no_migration;

    nr_migrations = thread_sched_ts_balance_migrate(runq, remote_runq);

    if (nr_migrations != 0)
        return;

    /*
     * If no thread could be pulled from the remote run queue, it means
     * its state has changed since the scan, and the new state has made
     * the run queue ineligible. Make another, simpler scan, and stop as
     * soon as some threads could be migrated successfully.
     */
    for (i = 0, nr_runqs = cpu_count(); i < nr_runqs; i++) {
        remote_runq = &thread_runqs[i];

        if (remote_runq == runq)
            continue;

        nr_migrations = thread_sched_ts_balance_migrate(runq, remote_runq);

        if (nr_migrations != 0)
            return;
    }

no_migration:
    spinlock_lock_intr_save(&runq->lock, &flags);

    /*
     * No thread could be migrated. Check the active run queue, as another
     * processor might have added threads while the balancer was running.
     * If the run queue is still empty, switch to the next round.
     */
    if (runq->ts_runq_active->nr_threads == 0)
        thread_sched_ts_start_next_round(runq);

    spinlock_unlock_intr_restore(&runq->lock, flags);
}

static void
thread_sched_idle_init_thread(struct thread *thread, unsigned short priority)
{
    (void)thread;
    (void)priority;
}

static struct thread_runq *
thread_sched_idle_select_runq(void)
{
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

static void
thread_sched_idle_put_prev(struct thread_runq *runq, struct thread *thread)
{
    (void)runq;
    (void)thread;
}

static struct thread *
thread_sched_idle_get_next(struct thread_runq *runq)
{
    return runq->idler;
}

static void
thread_sched_idle_tick(struct thread_runq *runq, struct thread *thread)
{
    (void)runq;
    (void)thread;
}

void __init
thread_bootstrap(void)
{
    size_t i;

    for (i = 0; i < ARRAY_SIZE(thread_runqs); i++)
        thread_runq_init(&thread_runqs[i]);

    tcb_set_current(&thread_idlers[0].tcb);
}

void __init
thread_ap_bootstrap(void)
{
    tcb_set_current(&thread_idlers[cpu_id()].tcb);
}

void __init
thread_setup(void)
{
    struct thread_sched_ops *ops;

    thread_policy_table[THREAD_SCHED_POLICY_FIFO] = THREAD_SCHED_CLASS_RT;
    thread_policy_table[THREAD_SCHED_POLICY_RR] = THREAD_SCHED_CLASS_RT;
    thread_policy_table[THREAD_SCHED_POLICY_TS] = THREAD_SCHED_CLASS_TS;
    thread_policy_table[THREAD_SCHED_POLICY_IDLE] = THREAD_SCHED_CLASS_IDLE;

    ops = &thread_sched_ops[THREAD_SCHED_CLASS_RT];
    ops->init_thread = thread_sched_rt_init_thread;
    ops->select_runq = thread_sched_rt_select_runq;
    ops->add = thread_sched_rt_add;
    ops->remove = thread_sched_rt_remove;
    ops->put_prev = thread_sched_rt_put_prev;
    ops->get_next = thread_sched_rt_get_next;
    ops->tick = thread_sched_rt_tick;

    ops = &thread_sched_ops[THREAD_SCHED_CLASS_TS];
    ops->init_thread = thread_sched_ts_init_thread;
    ops->select_runq = thread_sched_ts_select_runq;
    ops->add = thread_sched_ts_add;
    ops->remove = thread_sched_ts_remove;
    ops->put_prev = thread_sched_ts_put_prev;
    ops->get_next = thread_sched_ts_get_next;
    ops->tick = thread_sched_ts_tick;

    ops = &thread_sched_ops[THREAD_SCHED_CLASS_IDLE];
    ops->init_thread = thread_sched_idle_init_thread;
    ops->select_runq = thread_sched_idle_select_runq;
    ops->add = thread_sched_idle_add;
    ops->remove = thread_sched_idle_remove;
    ops->put_prev = thread_sched_idle_put_prev;
    ops->get_next = thread_sched_idle_get_next;
    ops->tick = thread_sched_idle_tick;

    bitmap_zero(thread_active_runqs, MAX_CPUS);

    thread_ts_highest_round = THREAD_TS_INITIAL_ROUND;

    kmem_cache_init(&thread_cache, "thread", sizeof(struct thread),
                    CPU_L1_SIZE, NULL, NULL, NULL, 0);
    kmem_cache_init(&thread_stack_cache, "thread_stack", STACK_SIZE,
                    DATA_ALIGN, NULL, NULL, NULL, 0);
}

static void
thread_main(void)
{
    struct thread *thread;

    assert(!cpu_intr_enabled());
    assert(!thread_preempt_enabled());

    spinlock_unlock(&thread_runq_local()->lock);
    cpu_intr_enable();
    thread_preempt_enable();

    thread = thread_self();
    thread->fn(thread->arg);

    /* TODO Thread destruction */
    for (;;)
        cpu_idle();
}

static void
thread_init_sched(struct thread *thread, unsigned short priority)
{
    thread_sched_ops[thread->sched_class].init_thread(thread, priority);
}

/*
 * This function initializes most thread members.
 *
 * It leaves the cpu member uninitialized.
 */
static void
thread_init(struct thread *thread, void *stack, const struct thread_attr *attr,
            void (*fn)(void *), void *arg)
{
    const char *name;
    struct task *task;

    tcb_init(&thread->tcb, stack, thread_main);

    if (attr == NULL)
        attr = &thread_default_attr;

    task = (attr->task == NULL) ? thread_self()->task : attr->task;
    assert(task != NULL);
    name = (attr->name == NULL) ? task->name : attr->name;
    assert(name != NULL);
    assert(attr->sched_policy < THREAD_NR_SCHED_POLICIES);

    /*
     * The expected interrupt, preemption and run queue lock state when
     * dispatching a thread is :
     *  - interrupts disabled
     *  - preemption disabled
     *  - run queue locked
     *
     * Locking the run queue increases the preemption counter once more,
     * making its value 2.
     */
    thread->flags = 0;
    thread->state = THREAD_SLEEPING;
    thread->pinned = 0;
    thread->preempt = 2;
    thread->on_rq = 0;
    thread->sched_policy = attr->sched_policy;
    thread->sched_class = thread_policy_table[attr->sched_policy];
    thread_init_sched(thread, attr->priority);
    thread->task = task;
    thread->stack = stack;
    strlcpy(thread->name, name, sizeof(thread->name));
    thread->fn = fn;
    thread->arg = arg;

    task_add_thread(task, thread);
}

int
thread_create(struct thread **threadp, const struct thread_attr *attr,
              void (*fn)(void *), void *arg)

{
    struct thread *thread;
    void *stack;
    int error;

    thread = kmem_cache_alloc(&thread_cache);

    if (thread == NULL) {
        error = ERROR_NOMEM;
        goto error_thread;
    }

    stack = kmem_cache_alloc(&thread_stack_cache);

    if (stack == NULL) {
        error = ERROR_NOMEM;
        goto error_stack;
    }

    thread_init(thread, stack, attr, fn, arg);
    thread_wakeup(thread);

    *threadp = thread;
    return 0;

error_stack:
    kmem_cache_free(&thread_cache, thread);
error_thread:
    return error;
}

void
thread_sleep(void)
{
    thread_self()->state = THREAD_SLEEPING;
    thread_schedule();
}

void
thread_wakeup(struct thread *thread)
{
    struct thread_runq *runq;
    unsigned long on_rq, flags;

    on_rq = atomic_cas(&thread->on_rq, 0, 1);

    if (on_rq)
        return;

    /*
     * Disable preemption and interrupts to avoid a deadlock in case the local
     * run queue is selected.
     */
    thread_preempt_disable();
    flags = cpu_intr_save();

    /* The returned run queue is locked */
    runq = thread_sched_ops[thread->sched_class].select_runq();
    spinlock_assert_locked(&runq->lock);
    thread_runq_wakeup(runq, thread);
    spinlock_unlock(&runq->lock);
    cpu_intr_restore(flags);
    thread_preempt_enable();
}

static void
thread_balancer(void *arg)
{
    struct thread_runq *runq;

    runq = arg;

    for (;;) {
        thread_sleep();
        thread_sched_ts_balance(runq);
    }
}

static void __init
thread_setup_balancer(void)
{
    char name[THREAD_NAME_SIZE];
    struct thread_runq *runq;
    struct thread_attr attr;
    struct thread *balancer;
    int error;

    runq = thread_runq_local();

    /*
     * Real-time threads are currently dispatched on the caller's run queue.
     *
     * TODO CPU affinity
     */
    snprintf(name, sizeof(name), "x15_balancer/%u", cpu_id());
    attr.task = kernel_task;
    attr.name = name;
    attr.sched_policy = THREAD_SCHED_CLASS_RT;
    attr.priority = THREAD_SCHED_RT_PRIO_MIN;
    error = thread_create(&balancer, &attr, thread_balancer, runq);

    if (error)
        panic("thread: unable to create balancer thread");

    runq->balancer = balancer;
}

static void
thread_idler(void *arg)
{
    (void)arg;

    for (;;)
        cpu_idle();
}

static void __init
thread_setup_idler(void)
{
    char name[THREAD_NAME_SIZE];
    struct thread_attr attr;
    struct thread *idler;
    unsigned int cpu;
    void *stack;

    stack = kmem_cache_alloc(&thread_stack_cache);

    if (stack == NULL)
        panic("thread: unable to allocate idler thread stack");

    /*
     * Having interrupts enabled was required to allocate the stack, but
     * at this stage, the idler thread is still the current thread, so disable
     * interrupts while initializing it.
     */
    cpu_intr_disable();

    cpu = cpu_id();
    snprintf(name, sizeof(name), "x15_idler/%u", cpu);
    attr.task = kernel_task;
    attr.name = name;
    attr.sched_policy = THREAD_SCHED_POLICY_IDLE;
    idler = &thread_idlers[cpu];
    thread_init(idler, stack, &attr, thread_idler, NULL);
    idler->state = THREAD_RUNNING;
    idler->cpu = cpu;
}

void __init
thread_run(void)
{
    struct thread_runq *runq;
    struct thread *thread;

    assert(cpu_intr_enabled());

    thread_setup_balancer();

    /* This call disables interrupts */
    thread_setup_idler();

    runq = thread_runq_local();
    spinlock_lock(&runq->lock);
    thread = thread_runq_get_next(thread_runq_local());

    /*
     * Locking the run queue increased the preemption counter to 3.
     * Artificially reduce it to the expected value.
     */
    thread_preempt_enable_no_resched();

    if (thread->task != kernel_task)
        pmap_load(thread->task->map->pmap);

    tcb_load(&thread->tcb);
}

static inline void
thread_switch(struct thread *prev, struct thread *next)
{
    if ((prev->task != next->task) && (next->task != kernel_task))
        pmap_load(next->task->map->pmap);

    tcb_switch(&prev->tcb, &next->tcb);
}

void
thread_schedule(void)
{
    struct thread_runq *runq;
    struct thread *prev, *next;
    unsigned long flags;

    assert(thread_preempt_enabled());

    prev = thread_self();

    do {
        thread_preempt_disable();
        runq = thread_runq_local();
        spinlock_lock_intr_save(&runq->lock, &flags);

        thread_clear_flag(prev, THREAD_RESCHEDULE);
        thread_runq_put_prev(runq, prev);

        if (prev->state != THREAD_RUNNING) {
            thread_runq_remove(runq, prev);
            atomic_swap(&prev->on_rq, 0);
        }

        next = thread_runq_get_next(runq);

        if (prev != next) {
            /*
             * That's where the true context switch occurs. The next thread
             * must unlock the run queue and reenable preemption.
             */
            thread_switch(prev, next);

            /*
             * When dispatched again, the thread might have been moved to
             * another processor.
             */
            runq = thread_runq_local();
        }

        spinlock_unlock_intr_restore(&runq->lock, flags);
        thread_preempt_enable_no_resched();
    } while (thread_test_flag(prev, THREAD_RESCHEDULE));
}

void
thread_reschedule(void)
{
    if (thread_test_flag(thread_self(), THREAD_RESCHEDULE)
        && thread_preempt_enabled())
        thread_schedule();
}

void
thread_tick(void)
{
    struct thread_runq *runq;
    struct thread *thread;

    assert(!cpu_intr_enabled());
    assert(!thread_preempt_enabled());

    runq = thread_runq_local();
    thread = thread_self();

    spinlock_lock(&runq->lock);
    thread_sched_ops[thread->sched_class].tick(runq, thread);
    spinlock_unlock(&runq->lock);
}
