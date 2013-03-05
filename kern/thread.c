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

#include <kern/assert.h>
#include <kern/error.h>
#include <kern/init.h>
#include <kern/kmem.h>
#include <kern/list.h>
#include <kern/macros.h>
#include <kern/panic.h>
#include <kern/param.h>
#include <kern/spinlock.h>
#include <kern/sprintf.h>
#include <kern/stddef.h>
#include <kern/string.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <machine/atomic.h>
#include <machine/cpu.h>
#include <machine/pmap.h>
#include <machine/tcb.h>
#include <vm/vm_map.h>

/*
 * Default time slice for real-time round-robin scheduling.
 */
#define THREAD_DEFAULT_RR_TIME_SLICE (HZ / 10)

/*
 * Run queue properties for real-time threads.
 */
struct thread_rt_runq {
    unsigned int bitmap;
    struct list threads[THREAD_SCHED_RT_PRIO_MAX + 1];
};

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
    struct thread_ts_group *current;
    unsigned int weight;
    unsigned int work;
};

/*
 * Per processor run queue.
 */
struct thread_runq {
    struct spinlock lock;
    struct thread *current;
    struct thread_rt_runq rt_runq;
    struct thread_ts_runq ts_runqs[2];
    struct thread_ts_runq *ts_runq_active;
    struct thread_ts_runq *ts_runq_expired;
    struct thread *idle;
} __aligned(CPU_L1_SIZE);

/*
 * Operations of a scheduling class.
 */
struct thread_sched_ops {
    void (*init_thread)(struct thread *thread, unsigned short priority);
    void (*add)(struct thread_runq *runq, struct thread *thread);
    void (*remove)(struct thread_runq *runq, struct thread *thread);
    void (*put_prev)(struct thread_runq *runq, struct thread *thread);
    struct thread * (*get_next)(struct thread_runq *runq);
    void (*tick)(struct thread_runq *runq, struct thread *thread);
};

static struct thread_runq thread_runqs[MAX_CPUS];

/*
 * Statically allocating the idle thread structures enables their use as
 * "current" threads during system bootstrap, which prevents migration and
 * preemption control functions from crashing.
 */
static struct thread thread_idles[MAX_CPUS];

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
    ts_runq->weight = 0;
    ts_runq->work = 0;
}

static void __init
thread_runq_init_ts(struct thread_runq *runq)
{
    runq->ts_runq_active = &runq->ts_runqs[0];
    runq->ts_runq_expired = &runq->ts_runqs[1];
    thread_ts_runq_init(runq->ts_runq_active);
    thread_ts_runq_init(runq->ts_runq_expired);
}

static void __init
thread_runq_init_idle(struct thread_runq *runq)
{
    struct thread *idle;

    /* Initialize what's needed during bootstrap */
    idle = &thread_idles[runq - thread_runqs];
    idle->flags = 0;
    idle->preempt = 1;
    idle->sched_policy = THREAD_SCHED_POLICY_IDLE;
    idle->sched_class = THREAD_SCHED_CLASS_IDLE;
    idle->task = kernel_task;
    runq->idle = idle;
}

static void __init
thread_runq_init(struct thread_runq *runq)
{
    spinlock_init(&runq->lock);
    thread_runq_init_rt(runq);
    thread_runq_init_ts(runq);
    thread_runq_init_idle(runq);
    runq->current = runq->idle;
}

static void
thread_runq_add(struct thread_runq *runq, struct thread *thread)
{
    assert(!cpu_intr_enabled());
    spinlock_assert_locked(&runq->lock);

    thread_sched_ops[thread->sched_class].add(runq, thread);

    if (thread->sched_class < runq->current->sched_class)
        runq->current->flags |= THREAD_RESCHEDULE;
}

static void
thread_runq_remove(struct thread_runq *runq, struct thread *thread)
{
    assert(!cpu_intr_enabled());
    spinlock_assert_locked(&runq->lock);

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

static inline struct thread_runq *
thread_runq_local(void)
{
    assert(!thread_preempt_enabled() || thread_pinned());
    return &thread_runqs[cpu_id()];
}

static void
thread_sched_rt_init_thread(struct thread *thread, unsigned short priority)
{
    assert(priority <= THREAD_SCHED_RT_PRIO_MAX);
    thread->rt_ctx.priority = priority;
    thread->rt_ctx.time_slice = THREAD_DEFAULT_RR_TIME_SLICE;
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
        runq->current->flags |= THREAD_RESCHEDULE;
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
    thread->flags |= THREAD_RESCHEDULE;
}

static void
thread_sched_ts_init_thread(struct thread *thread, unsigned short priority)
{
    assert(priority <= THREAD_SCHED_TS_PRIO_MAX);
    thread->ts_ctx.ts_runq = NULL;
    thread->ts_ctx.weight = priority + 1;
    thread->ts_ctx.work = 0;
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
thread_sched_ts_enqueue(struct thread_ts_runq *ts_runq, struct thread *thread)
{
    struct thread_ts_group *group, *tmp;
    struct list *node, *init_node;
    unsigned int thread_work, group_work, group_weight, total_weight;

    assert(thread->ts_ctx.ts_runq == NULL);

    group = &ts_runq->group_array[thread->ts_ctx.weight - 1];
    group_weight = group->weight + thread->ts_ctx.weight;

    /* TODO Limit the maximum number of threads to prevent this situation */
    if (group_weight < group->weight)
        panic("thread: weight overflow");

    total_weight = ts_runq->weight + thread->ts_ctx.weight;

    if (total_weight < ts_runq->weight)
        panic("thread: weight overflow");

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

    ts_runq->weight = total_weight;
    group->weight = group_weight;
    thread->ts_ctx.work = thread_work;
    list_insert_tail(&group->threads, &thread->ts_ctx.node);
    thread->ts_ctx.ts_runq = ts_runq;
}

static void
thread_sched_ts_restart(struct thread_ts_runq *ts_runq)
{
    struct list *node;

    node = list_first(&ts_runq->groups);
    assert(node != NULL);
    ts_runq->current = list_entry(node, struct thread_ts_group, node);
    thread_self()->flags |= THREAD_RESCHEDULE;
}

static void
thread_sched_ts_add(struct thread_runq *runq, struct thread *thread)
{
    struct thread_ts_runq *ts_runq;

    ts_runq = runq->ts_runq_active;
    thread_sched_ts_enqueue(ts_runq, thread);
    thread_sched_ts_restart(ts_runq);
}

static unsigned int
thread_sched_ts_dequeue_scale(unsigned int group_work,
                              unsigned int old_group_weight,
                              unsigned int new_group_weight)
{
#ifndef __LP64__
    if (likely((group_work < 0x10000) && (new_group_weight < 0x10000)))
        return DIV_CEIL(group_work * new_group_weight, old_group_weight);
#endif /* __LP64__ */

    return (unsigned int)DIV_CEIL((unsigned long long)group_work
                                  * new_group_weight,
                                  old_group_weight);
}

static void
thread_sched_ts_dequeue(struct thread *thread)
{
    struct thread_ts_runq *ts_runq;
    struct thread_ts_group *group, *tmp;
    struct list *node, *init_node;
    unsigned int thread_work, group_work, group_weight;

    assert(thread->ts_ctx.ts_runq != NULL);

    ts_runq = thread->ts_ctx.ts_runq;
    group = &ts_runq->group_array[thread->ts_ctx.weight - 1];

    thread->ts_ctx.ts_runq = NULL;
    list_remove(&thread->ts_ctx.node);
    group_weight = group->weight - thread->ts_ctx.weight;
    group_work = thread_sched_ts_dequeue_scale(group->work, group->weight,
                                               group_weight);
    thread_work = group->work - group_work;
    ts_runq->work -= thread_work;
    group->work = group_work;
    ts_runq->weight -= thread->ts_ctx.weight;
    group->weight -= thread->ts_ctx.weight;

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
thread_sched_ts_start_next_round(struct thread_runq *runq)
{
    struct thread_ts_runq *ts_runq;

    ts_runq = runq->ts_runq_expired;
    runq->ts_runq_expired = runq->ts_runq_active;
    runq->ts_runq_active = ts_runq;

    if (ts_runq->weight != 0)
        thread_sched_ts_restart(ts_runq);
}

static void
thread_sched_ts_remove(struct thread_runq *runq, struct thread *thread)
{
    struct thread_ts_runq *ts_runq;

    ts_runq = thread->ts_ctx.ts_runq;
    thread_sched_ts_dequeue(thread);

    if (ts_runq == runq->ts_runq_active) {
        if (ts_runq->weight == 0)
            thread_sched_ts_start_next_round(runq);
        else
            thread_sched_ts_restart(ts_runq);
    }
}

static void
thread_sched_ts_deactivate(struct thread_runq *runq, struct thread *thread)
{
    assert(thread->ts_ctx.ts_runq == runq->ts_runq_active);

    thread_sched_ts_dequeue(thread);
    thread_sched_ts_enqueue(runq->ts_runq_expired, thread);

    if (runq->ts_runq_active->weight == 0)
        thread_sched_ts_start_next_round(runq);
}

static void
thread_sched_ts_put_prev(struct thread_runq *runq, struct thread *thread)
{
    static int unfair = 0;
    struct thread_ts_runq *ts_runq;
    struct thread_ts_group *group;

    ts_runq = runq->ts_runq_active;
    group = &ts_runq->group_array[thread->ts_ctx.weight - 1];
    list_insert_tail(&group->threads, &thread->ts_ctx.node);

    if (thread->ts_ctx.work >= thread->ts_ctx.weight) {
        if (likely(!unfair))
            if (unlikely(thread->ts_ctx.work > thread->ts_ctx.weight)) {
                unfair = 1;
                printk("thread: warning: preemption disabled too long is "
                       "causing scheduling unfairness\n");
            }

        thread_sched_ts_deactivate(runq, thread);
    }
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

    if (ts_runq->weight == 0)
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
    thread = list_first_entry(&group->threads, struct thread, ts_ctx.node);
    list_remove(&thread->ts_ctx.node);
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
    thread->flags |= THREAD_RESCHEDULE;
    thread->ts_ctx.work++;
}

static void
thread_sched_idle_init_thread(struct thread *thread, unsigned short priority)
{
    (void)thread;
    (void)priority;
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
    return runq->idle;
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

    tcb_set_current(&thread_idles[0].tcb);
}

void __init
thread_ap_bootstrap(void)
{
    tcb_set_current(&thread_idles[cpu_id()].tcb);
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
    ops->add = thread_sched_rt_add;
    ops->remove = thread_sched_rt_remove;
    ops->put_prev = thread_sched_rt_put_prev;
    ops->get_next = thread_sched_rt_get_next;
    ops->tick = thread_sched_rt_tick;

    ops = &thread_sched_ops[THREAD_SCHED_CLASS_TS];
    ops->init_thread = thread_sched_ts_init_thread;
    ops->add = thread_sched_ts_add;
    ops->remove = thread_sched_ts_remove;
    ops->put_prev = thread_sched_ts_put_prev;
    ops->get_next = thread_sched_ts_get_next;
    ops->tick = thread_sched_ts_tick;

    ops = &thread_sched_ops[THREAD_SCHED_CLASS_IDLE];
    ops->init_thread = thread_sched_idle_init_thread;
    ops->add = thread_sched_idle_add;
    ops->remove = thread_sched_idle_remove;
    ops->put_prev = thread_sched_idle_put_prev;
    ops->get_next = thread_sched_idle_get_next;
    ops->tick = thread_sched_idle_tick;

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

    /* TODO Multiprocessor thread dispatching */
    thread->cpu = cpu_id();
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

    /* TODO Multiprocessor thread dispatching */
    assert(thread->cpu == cpu_id());

    on_rq = atomic_cas(&thread->on_rq, 0, 1);

    if (on_rq)
        return;

    thread->state = THREAD_RUNNING;

    thread_pin();
    runq = thread_runq_local();
    spinlock_lock_intr_save(&runq->lock, &flags);
    thread_runq_add(runq, thread);
    spinlock_unlock_intr_restore(&runq->lock, flags);
    thread_unpin();

    thread_reschedule();
}

static void
thread_idle(void *arg)
{
    (void)arg;

    for (;;)
        cpu_idle();
}

static void __init
thread_setup_idle(void)
{
    char name[THREAD_NAME_SIZE];
    struct thread_attr attr;
    struct thread *thread;
    unsigned int cpu;
    void *stack;

    stack = kmem_cache_alloc(&thread_stack_cache);

    if (stack == NULL)
        panic("thread: unable to allocate idle thread stack");

    /*
     * Having interrupts enabled was required to allocate the stack, but
     * at this stage, the idle thread is still the current thread, so disable
     * interrupts while initializing it.
     */
    cpu_intr_disable();

    cpu = cpu_id();
    snprintf(name, sizeof(name), "idle%u", cpu);
    attr.task = kernel_task;
    attr.name = name;
    attr.sched_policy = THREAD_SCHED_POLICY_IDLE;
    thread = &thread_idles[cpu];
    thread_init(thread, stack, &attr, thread_idle, NULL);
    thread->state = THREAD_RUNNING;
    thread->cpu = cpu;
}

void __init
thread_run(void)
{
    struct thread_runq *runq;
    struct thread *thread;

    assert(cpu_intr_enabled());

    /* This call disables interrupts */
    thread_setup_idle();

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

        prev->flags &= ~THREAD_RESCHEDULE;
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
    } while (prev->flags & THREAD_RESCHEDULE);
}

void
thread_reschedule(void)
{
    if ((thread_self()->flags & THREAD_RESCHEDULE) && thread_preempt_enabled())
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
