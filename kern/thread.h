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
 * Type for thread entry point.
 */
typedef void (*thread_run_fn_t)(void *);

/*
 * Thread structure.
 */
struct thread {
    struct tcb *tcb;
    struct list runq_node;
    struct list task_node;
    struct task *task;
    void *stack;
    char name[THREAD_NAME_SIZE];
    thread_run_fn_t run_fn;
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
                  thread_run_fn_t run_fn, void *arg);

/*
 * Transform into a thread.
 *
 * This function is used during system initialization by code in "boot context"
 * when creating the first thread on their processor.
 */
void __noreturn thread_load(struct thread *thread);

/*
 * Thread entry point.
 */
void __noreturn thread_main(struct thread *thread);

#endif /* _KERN_THREAD_H */
