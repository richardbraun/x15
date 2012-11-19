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

#include <kern/list.h>
#include <kern/macros.h>
#include <kern/task.h>
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
    int flags;
    struct list runq_node;
    struct list task_node;
    struct task *task;
    void *stack;
    char name[THREAD_NAME_SIZE];
    void (*fn)(void *);
    void *arg;
};

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

#endif /* _KERN_THREAD_H */
