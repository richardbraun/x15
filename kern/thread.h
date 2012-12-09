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

#ifndef _KERN_THREAD_H
#define _KERN_THREAD_H

#include <kern/assert.h>
#include <kern/list.h>
#include <kern/macros.h>
#include <kern/param.h>
#include <kern/task.h>
#include <machine/cpu.h>
#include <machine/tcb.h>

/*
 * Thread name buffer size.
 */
#define THREAD_NAME_SIZE 32

/*
 * Thread flags.
 */
#define THREAD_RESCHEDULE   0x1 /* Thread marked for reschedule */

/*
 * Thread structure.
 */
struct thread {
    struct tcb tcb;
    short flags;
    unsigned short preempt;
    struct list runq_node;
    struct list task_node;
    struct task *task;
    void *stack;
    char name[THREAD_NAME_SIZE];
    void (*fn)(void *);
    void *arg;
};

/*
 * Per processor run queue.
 */
struct thread_runq {
    struct thread *current;
    struct list threads;
} __aligned(CPU_L1_SIZE);

extern struct thread_runq thread_runqs[MAX_CPUS];

/*
 * Initialize the thread module.
 */
void thread_setup(void);

/*
 * Create a thread.
 *
 * If the given name is null, the task name is used instead.
 */
int thread_create(struct thread **threadp, const char *name, struct task *task,
                  void (*fn)(void *), void *arg);

/*
 * Start running threads on the local processor.
 *
 * Interrupts are implicitely enabled when the first thread is dispatched.
 */
void __noreturn thread_run(void);

/*
 * Invoke the scheduler.
 */
void thread_schedule(void);

/*
 * Invoke the scheduler if the current thread is marked for reschedule.
 *
 * Called from interrupt context.
 */
void thread_reschedule(void);

/*
 * Report a periodic timer interrupt on the thread currently running on
 * the local processor.
 *
 * Called from interrupt context.
 */
void thread_tick(void);

static inline struct thread_runq *
thread_runq_local(void)
{
    return &thread_runqs[cpu_id()];
}

static inline struct thread *
thread_current(void)
{
    return thread_runq_local()->current;
}

/*
 * Preemption control functions.
 */

static inline int
thread_preempt_enabled(void)
{
    return (thread_current()->preempt == 0);
}

static inline void
thread_preempt_enable_no_resched(void)
{
    struct thread *thread;

    thread = thread_current();
    assert(thread->preempt != 0);
    thread->preempt--;
}

static inline void
thread_preempt_enable(void)
{
    struct thread *thread;

    thread = thread_current();
    assert(thread->preempt != 0);
    thread->preempt--;

    if ((thread->preempt == 0) && (thread->flags & THREAD_RESCHEDULE))
        thread_schedule();
}

static inline void
thread_preempt_disable(void)
{
    struct thread *thread;

    thread = thread_current();
    thread->preempt++;
    assert(thread->preempt != 0);
}

#endif /* _KERN_THREAD_H */
