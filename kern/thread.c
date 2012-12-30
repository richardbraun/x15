/*
 * Copyright (c) 2012 Richard Braun.
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
 * Per processor run queue.
 */
struct thread_runq {
    struct thread *idle;
    struct list threads;
} __aligned(CPU_L1_SIZE);

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

static void __init
thread_runq_init(struct thread_runq *runq, struct thread *idle)
{
    /* Consider migration and preemption disabled during initialization */
    idle->flags = 0;
    idle->pinned = 1;
    idle->preempt = 1;
    runq->idle = idle;
    list_init(&runq->threads);
}

static void
thread_runq_enqueue(struct thread_runq *runq, struct thread *thread)
{
    assert(!cpu_intr_enabled());
    list_insert_tail(&runq->threads, &thread->runq_node);
}

static struct thread *
thread_runq_dequeue(struct thread_runq *runq)
{
    struct thread *thread;

    assert(!cpu_intr_enabled());

    if (list_empty(&runq->threads))
        thread = NULL;
    else {
        thread = list_first_entry(&runq->threads, struct thread, runq_node);
        list_remove(&thread->runq_node);
    }

    return thread;
}

static inline struct thread_runq *
thread_runq_local(void)
{
    return &thread_runqs[cpu_id()];
}

void __init
thread_bootstrap(void)
{
    size_t i;

    for (i = 0; i < ARRAY_SIZE(thread_runqs); i++)
        thread_runq_init(&thread_runqs[i], &thread_idles[i]);

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

    thread = thread_current();
    cpu_intr_enable();
    thread_preempt_enable();

    thread->fn(thread->arg);

    /* TODO Thread destruction */
    for (;;)
        cpu_idle();
}

static void
thread_init(struct thread *thread, struct task *task, void *stack,
            const char *name, void (*fn)(void *), void *arg)
{
    tcb_init(&thread->tcb, stack, thread_main);

    if (name == NULL)
        name = task->name;

    thread->flags = 0;
    thread->pinned = 0;
    thread->preempt = 1;
    thread->task = task;
    thread->stack = stack;
    strlcpy(thread->name, name, sizeof(thread->name));
    thread->fn = fn;
    thread->arg = arg;
    task_add_thread(task, thread);
}

int
thread_create(struct thread **threadp, struct task *task, const char *name,
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

    thread_init(thread, task, stack, name, fn, arg);

    flags = cpu_intr_save();
    thread_runq_enqueue(&thread_runqs[cpu_id()], thread);
    cpu_intr_restore(flags);

    *threadp = thread;
    return 0;

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
    struct thread_runq *runq;
    void *stack;

    stack = kmem_cache_alloc(&thread_stack_cache);

    if (stack == NULL)
        panic("thread: unable to allocate idle thread stack");

    snprintf(name, sizeof(name), "idle%u", cpu_id());
    runq = thread_runq_local();
    thread_init(runq->idle, kernel_task, stack, name, thread_idle, NULL);
}

void __init
thread_run(void)
{
    struct thread_runq *runq;
    struct thread *thread;

    assert(cpu_intr_enabled());

    thread_setup_idle();

    cpu_intr_disable();
    runq = thread_runq_local();
    thread = thread_runq_dequeue(runq);

    if (thread == NULL)
        thread = runq->idle;

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
        prev = thread_current();
        assert(prev != NULL);

        if (prev != runq->idle)
            thread_runq_enqueue(runq, prev);

        prev->flags &= ~THREAD_RESCHEDULE;
        next = thread_runq_dequeue(runq);

        if (next == NULL)
            next = runq->idle;

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

    thread = thread_current();
    assert(thread != NULL);

    if ((thread->preempt == 0) && (thread->flags & THREAD_RESCHEDULE))
        thread_schedule();
}

void
thread_preempt_schedule(void)
{
    struct thread *thread;

    thread = thread_current();
    assert(thread != NULL);

    if ((thread->preempt == 0))
        thread_schedule();
}

void
thread_tick(void)
{
    struct thread *thread;

    assert(!cpu_intr_enabled());

    thread = thread_current();
    assert(thread != NULL);
    thread->flags |= THREAD_RESCHEDULE;
}
