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

#include <kern/error.h>
#include <kern/init.h>
#include <kern/kmem.h>
#include <kern/list.h>
#include <kern/macros.h>
#include <kern/param.h>
#include <kern/stddef.h>
#include <kern/string.h>
#include <kern/thread.h>
#include <machine/cpu.h>
#include <machine/tcb.h>

/*
 * Per processor run queue.
 */
struct thread_runq {
    struct thread *current;
    struct list threads;
} __aligned(CPU_L1_SIZE);

static struct thread_runq thread_runqs[MAX_CPUS];

/*
 * Caches for allocated threads and their stacks.
 */
static struct kmem_cache thread_cache;
static struct kmem_cache thread_stack_cache;

static void __init
thread_runq_init(struct thread_runq *runq)
{
    runq->current = NULL;
    list_init(&runq->threads);
}

static void
thread_runq_enqueue(struct thread_runq *runq, struct thread *thread)
{
    list_insert_tail(&runq->threads, &thread->runq_node);
}

static struct thread *
thread_runq_dequeue(struct thread_runq *runq)
{
    struct thread *thread;

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
thread_setup(void)
{
    size_t i;

    kmem_cache_init(&thread_cache, "thread", sizeof(struct thread),
                    CPU_L1_SIZE, NULL, NULL, NULL, 0);
    kmem_cache_init(&thread_stack_cache, "thread_stack", STACK_SIZE,
                    CPU_L1_SIZE, NULL, NULL, NULL, 0);

    for (i = 0; i < ARRAY_SIZE(thread_runqs); i++)
        thread_runq_init(&thread_runqs[i]);
}

static void
thread_main(void)
{
    struct thread_runq *runq;
    struct thread *thread;

    assert(!cpu_intr_enabled());

    runq = thread_runq_local();
    thread = runq->current;
    cpu_intr_enable();

    thread->fn(thread->arg);

    for (;;)
        cpu_idle();
}

int
thread_create(struct thread **threadp, const char *name, struct task *task,
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

    tcb_init(&thread->tcb, stack, thread_main);

    if (name == NULL)
        name = task->name;

    thread->flags = 0;
    thread->task = task;
    thread->stack = stack;
    strlcpy(thread->name, name, sizeof(thread->name));
    thread->fn = fn;
    thread->arg = arg;

    /* XXX Assign all threads to the main processor for now */
    thread_runq_enqueue(&thread_runqs[0], thread);
    task_add_thread(task, thread);

    *threadp = thread;
    return 0;

error_stack:
    kmem_cache_free(&thread_cache, thread);
error_thread:
    return error;
}

void __init
thread_run(void)
{
    struct thread_runq *runq;
    struct thread *thread;

    runq = thread_runq_local();

    thread = thread_runq_dequeue(runq);

    /* TODO Idle thread */
    assert(thread != NULL);

    runq->current = thread;
    tcb_load(&thread->tcb);
}

void
thread_schedule(void)
{
    struct thread_runq *runq;
    struct thread *prev, *next;
    unsigned long flags;

    flags = cpu_intr_save();

    runq = thread_runq_local();
    prev = runq->current;
    thread_runq_enqueue(runq, prev);
    next = thread_runq_dequeue(runq);

    /* TODO Idle thread */
    assert(next != NULL);

    if (prev != next) {
        runq->current = next;
        tcb_switch(&prev->tcb, &next->tcb);
    }

    cpu_intr_restore(flags);
}

void
thread_reschedule(void)
{
    struct thread_runq *runq;
    struct thread *thread;

    assert(!cpu_intr_enabled());

    runq = thread_runq_local();
    thread = runq->current;

    /* TODO Idle thread */
    assert(thread != NULL);

    if (thread->flags & THREAD_RESCHEDULE)
        thread_schedule();
}

void
thread_tick(void)
{
    struct thread_runq *runq;
    struct thread *thread;

    assert(!cpu_intr_enabled());

    runq = thread_runq_local();
    thread = runq->current;

    /* TODO Idle thread */
    assert(thread != NULL);

    thread->flags |= THREAD_RESCHEDULE;
}
