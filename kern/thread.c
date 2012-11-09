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
 * Make sure thread stacks are properly aligned.
 */
#define THREAD_STACK_ALIGN 8

/*
 * Per processor run queue.
 */
struct thread_runq {
    struct list threads;
} __aligned(CPU_L1_SIZE);

/*
 * Per-processor run queues.
 */
static struct thread_runq thread_runqs[MAX_CPUS];

/*
 * Caches for allocated threads and their stacks.
 */
static struct kmem_cache thread_cache;
static struct kmem_cache thread_stack_cache;

static void __init
thread_runq_init(struct thread_runq *runq)
{
    list_init(&runq->threads);
}

void __init
thread_setup(void)
{
    size_t i;

    tcb_setup();

    kmem_cache_init(&thread_cache, "thread", sizeof(struct thread),
                    0, NULL, NULL, NULL, 0);
    kmem_cache_init(&thread_stack_cache, "thread_stack", STACK_SIZE,
                    THREAD_STACK_ALIGN, NULL, NULL, NULL, 0);

    for (i = 0; i < ARRAY_SIZE(thread_runqs); i++)
        thread_runq_init(&thread_runqs[i]);
}

int
thread_create(struct thread **threadp, const char *name, struct task *task,
              thread_run_fn_t run_fn, void *arg)
{
    struct thread *thread;
    struct tcb *tcb;
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

    error = tcb_create(&tcb, stack, thread);

    if (error)
        goto error_tcb;

    if (name == NULL)
        name = task->name;

    /* XXX Assign all threads to the main processor for now */
    thread->tcb = tcb;
    list_insert_tail(&thread_runqs[0].threads, &thread->runq_node);
    task_add_thread(task, thread);
    thread->task = task;
    thread->stack = stack;
    strlcpy(thread->name, name, sizeof(thread->name));
    thread->run_fn = run_fn;
    thread->arg = arg;
    *threadp = thread;
    return 0;

error_tcb:
    kmem_cache_free(&thread_stack_cache, stack);
error_stack:
    kmem_cache_free(&thread_cache, thread);
error_thread:
    return error;
}

void __init
thread_load(struct thread *thread)
{
    tcb_load(thread->tcb);
}

void
thread_main(struct thread *thread)
{
    thread->run_fn(thread->arg);

    for (;;)
        cpu_idle();
}
