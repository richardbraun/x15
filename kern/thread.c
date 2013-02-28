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
#include <kern/sprintf.h>
#include <kern/stddef.h>
#include <kern/string.h>
#include <kern/task.h>
#include <kern/thread.h>
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
    struct thread_rt_runq rt_runq;
    struct thread_ts_runq ts_runq;
    struct thread *idle;
} __aligned(CPU_L1_SIZE);

/*
 * Operations of a scheduling class.
 */
struct thread_sched_ops {
    void (*init_thread)(struct thread *thread, unsigned short priority);
    int (*add)(struct thread_runq *runq, struct thread *thread);
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
thread_runq_init_ts(struct thread_runq *runq)
{
    struct thread_ts_runq *ts_runq;
    size_t i;

    ts_runq = &runq->ts_runq;

    for (i = 0; i < ARRAY_SIZE(ts_runq->group_array); i++)
        thread_ts_group_init(&ts_runq->group_array[i]);

    list_init(&ts_runq->groups);
    ts_runq->current = NULL;
    ts_runq->weight = 0;
    ts_runq->work = 0;
}

static void __init
thread_runq_init_idle(struct thread_runq *runq)
{
    struct thread *idle;

    /* Make sure preemption is disabled during initialization */
    idle = &thread_idles[runq - thread_runqs];
    idle->flags = 0;
    idle->preempt = 1;
    idle->task = kernel_task;
    runq->idle = idle;
}

static void __init
thread_runq_init(struct thread_runq *runq)
{
    thread_runq_init_rt(runq);
    thread_runq_init_ts(runq);
    thread_runq_init_idle(runq);
}

static int
thread_runq_add(struct thread_runq *runq, struct thread *thread)
{
    assert(!cpu_intr_enabled());

    return thread_sched_ops[thread->sched_class].add(runq, thread);
}

static void
thread_runq_put_prev(struct thread_runq *runq, struct thread *thread)
{
    assert(!cpu_intr_enabled());

    thread_sched_ops[thread->sched_class].put_prev(runq, thread);
}

static struct thread *
thread_runq_get_next(struct thread_runq *runq)
{
    struct thread *thread;
    unsigned int i;

    assert(!cpu_intr_enabled());

    for (i = 0; i < ARRAY_SIZE(thread_sched_ops); i++) {
        thread = thread_sched_ops[i].get_next(runq);

        if (thread != NULL)
            return thread;
    }

    /* The idle class should never be empty */
    panic("thread: unable to find next thread");
}

static inline struct thread_runq *
thread_runq_local(void)
{
    return &thread_runqs[cpu_id()];
}

static void
thread_sched_rt_init_thread(struct thread *thread, unsigned short priority)
{
    assert(priority <= THREAD_SCHED_RT_PRIO_MAX);
    thread->rt_ctx.priority = priority;
    thread->rt_ctx.time_slice = THREAD_DEFAULT_RR_TIME_SLICE;
}

static int
thread_sched_rt_add(struct thread_runq *runq, struct thread *thread)
{
    struct thread_rt_runq *rt_runq;
    struct list *threads;

    rt_runq = &runq->rt_runq;
    threads = &rt_runq->threads[thread->rt_ctx.priority];
    list_insert_tail(threads, &thread->rt_ctx.node);

    if (list_singular(threads))
        rt_runq->bitmap |= (1U << thread->rt_ctx.priority);

    return 0;
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
    thread->ts_ctx.weight = priority + 1;
}

static unsigned int
thread_sched_ts_add_scale(unsigned int total_work, unsigned int total_weight,
                          unsigned short thread_weight)
{
    assert(total_weight != 0);

#ifndef __LP64__
    if (likely(total_work < 0x10000))
        return (total_work * thread_weight) / total_weight;
#endif /* __LP64__ */

    return (unsigned int)(((unsigned long long)total_work * thread_weight)
                          / total_weight);
}

static unsigned int
thread_sched_ts_add_scale_group(unsigned int group_work,
                                unsigned int old_group_weight,
                                unsigned int new_group_weight)
{
#ifndef __LP64__
    if (likely((group_work < 0x10000) && (new_group_weight < 0x10000)))
        return (group_work * new_group_weight) / old_group_weight;
#endif /* __LP64__ */

    return (unsigned int)(((unsigned long long)group_work * new_group_weight)
                          / old_group_weight);
}

static int
thread_sched_ts_add(struct thread_runq *runq, struct thread *thread)
{
    struct thread_ts_runq *ts_runq;
    struct thread_ts_group *group, *tmp;
    struct list *node, *init_node;
    unsigned int work, group_weight, total_weight;

    ts_runq = &runq->ts_runq;
    group = &ts_runq->group_array[thread->ts_ctx.weight - 1];

    group_weight = group->weight + thread->ts_ctx.weight;

    if (group_weight < group->weight)
        return ERROR_AGAIN;

    total_weight = ts_runq->weight + thread->ts_ctx.weight;

    if (total_weight < ts_runq->weight)
        return ERROR_AGAIN;

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

    if (ts_runq->current == NULL)
        ts_runq->current = group;
    else {
        work = (group->weight == 0)
               ? thread_sched_ts_add_scale(ts_runq->work, ts_runq->weight,
                                           thread->ts_ctx.weight)
               : thread_sched_ts_add_scale_group(group->work, group->weight,
                                                 group_weight);

        assert(work <= thread->ts_ctx.weight);
        ts_runq->work += work;
        group->work += work;
    }

    ts_runq->weight = total_weight;
    group->weight = group_weight;
    list_insert_tail(&group->threads, &thread->ts_ctx.node);
    return 0;
}

static unsigned int
thread_sched_ts_remove_scale(unsigned int group_work,
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
thread_sched_ts_remove(struct thread_runq *runq, struct thread *thread)
{
    struct thread_ts_runq *ts_runq;
    struct thread_ts_group *group, *tmp;
    struct list *node, *init_node;
    unsigned int work, group_weight;

    ts_runq = &runq->ts_runq;
    group = &ts_runq->group_array[thread->ts_ctx.weight - 1];

    list_remove(&thread->ts_ctx.node);

    group_weight = group->weight - thread->ts_ctx.weight;
    work = thread_sched_ts_remove_scale(group->work, group->weight,
                                        group_weight);
    assert(work <= thread->ts_ctx.weight);
    group->weight -= thread->ts_ctx.weight;
    assert(work <= group->work);
    group->work -= work;
    ts_runq->weight -= thread->ts_ctx.weight;
    assert(work <= ts_runq->work);
    ts_runq->work -= work;

    if (ts_runq->weight == 0)
        ts_runq->current = NULL;

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
thread_sched_ts_put_prev(struct thread_runq *runq, struct thread *thread)
{
    struct thread_ts_runq *ts_runq;
    struct thread_ts_group *group;

    ts_runq = &runq->ts_runq;
    group = &ts_runq->group_array[thread->ts_ctx.weight - 1];
    assert(group == ts_runq->current);

    list_insert_tail(&group->threads, &thread->ts_ctx.node);
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

    ts_runq = &runq->ts_runq;

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
thread_sched_ts_reset(struct thread_ts_runq *ts_runq)
{
    static int unfair;
    struct thread_ts_group *group;

    ts_runq->work = 0;

    list_for_each_entry(&ts_runq->groups, group, node) {
        if (likely(!unfair))
            if (unlikely(group->work != group->weight)) {
                unfair = 1;
                printk("thread: warning: preemption disabled too long is "
                       "causing scheduling unfairness\n");
            }

        group->work = 0;
    }
}

static void
thread_sched_ts_tick(struct thread_runq *runq, struct thread *thread)
{
    struct thread_ts_runq *ts_runq;
    struct thread_ts_group *group;

    ts_runq = &runq->ts_runq;
    group = &ts_runq->group_array[thread->ts_ctx.weight - 1];
    assert(group == ts_runq->current);

    thread->flags |= THREAD_RESCHEDULE;

    group->work++;
    ts_runq->work++;

    if (ts_runq->work == ts_runq->weight)
        thread_sched_ts_reset(ts_runq);
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

static int
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

    thread = thread_self();
    cpu_intr_enable();
    thread_preempt_enable();

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

    thread->flags = 0;
    thread->pinned = 0;
    thread->preempt = 1;
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
    unsigned long flags;
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

    flags = cpu_intr_save();
    error = thread_runq_add(&thread_runqs[cpu_id()], thread);
    cpu_intr_restore(flags);

    if (error)
        goto error_runq;

    *threadp = thread;
    return 0;

error_runq:
    kmem_cache_free(&thread_stack_cache, stack);
error_stack:
    kmem_cache_free(&thread_cache, thread);
error_thread:
    return error;
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
    thread_init(&thread_idles[cpu], stack, &attr, thread_idle, NULL);
}

void __init
thread_run(void)
{
    struct thread *thread;

    assert(cpu_intr_enabled());

    /* This call disables interrupts */
    thread_setup_idle();

    thread = thread_runq_get_next(thread_runq_local());

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

    do {
        thread_preempt_disable();
        flags = cpu_intr_save();

        runq = thread_runq_local();
        prev = thread_self();
        prev->flags &= ~THREAD_RESCHEDULE;
        thread_runq_put_prev(runq, prev);
        next = thread_runq_get_next(runq);

        if (prev != next)
            thread_switch(prev, next);

        cpu_intr_restore(flags);
        thread_preempt_enable_no_resched();
    } while (prev->flags & THREAD_RESCHEDULE);
}

void
thread_intr_schedule(void)
{
    struct thread *thread;

    assert(!cpu_intr_enabled());

    thread = thread_self();
    assert(thread != NULL);

    if ((thread->preempt == 0) && (thread->flags & THREAD_RESCHEDULE))
        thread_schedule();
}

void
thread_preempt_schedule(void)
{
    struct thread *thread;

    thread = thread_self();
    assert(thread != NULL);

    if ((thread->preempt == 0))
        thread_schedule();
}

void
thread_tick(void)
{
    struct thread *thread;

    assert(!cpu_intr_enabled());

    thread = thread_self();
    thread_preempt_disable();
    thread_sched_ops[thread->sched_class].tick(thread_runq_local(), thread);
    thread_preempt_enable_no_resched();
}
