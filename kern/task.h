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
 */

#ifndef _KERN_TASK_H
#define _KERN_TASK_H

#include <kern/atomic.h>
#include <kern/init.h>
#include <kern/list.h>
#include <kern/macros.h>
#include <kern/spinlock.h>
#include <kern/thread.h>
#include <vm/vm_map.h>

/*
 * Task name buffer size.
 */
#define TASK_NAME_SIZE 32

/*
 * Task structure.
 */
struct task {
    unsigned long nr_refs;
    struct spinlock lock;
    struct list node;
    struct list threads;
    struct vm_map *map;
    char name[TASK_NAME_SIZE];
};

static inline struct task *
task_get_kernel_task(void)
{
    extern struct task task_kernel_task;

    return &task_kernel_task;
}

static inline void
task_ref(struct task *task)
{
    __unused unsigned long nr_refs;

    nr_refs = atomic_fetch_add(&task->nr_refs, 1, ATOMIC_RELAXED);
    assert(nr_refs != (unsigned long)-1);
}

static inline void
task_unref(struct task *task)
{
    unsigned long nr_refs;

    nr_refs = atomic_fetch_sub_acq_rel(&task->nr_refs, 1);
    assert(nr_refs != 0);

    if (nr_refs == 1) {
        /* TODO Task destruction */
    }
}

static inline struct vm_map *
task_get_vm_map(const struct task *task)
{
    return task->map;
}

/*
 * Create a task.
 */
int task_create(struct task **taskp, const char *name);

/*
 * Look up a task from its name.
 *
 * If a task is found, it gains a reference. Otherwise, NULL is returned.
 *
 * This function is meant for debugging only.
 */
struct task * task_lookup(const char *name);

/*
 * Add a thread to a task.
 */
void task_add_thread(struct task *task, struct thread *thread);

/*
 * Remove a thread from a task.
 */
void task_remove_thread(struct task *task, struct thread *thread);

/*
 * Look up a thread in a task from its name.
 *
 * If a thread is found, it gains a reference, Otherwise, NULL is returned.
 *
 * This function is meant for debugging only.
 */
struct thread * task_lookup_thread(struct task *task, const char *name);

/*
 * Display task information.
 *
 * If task is NULL, this function displays all tasks.
 */
void task_info(struct task *task);

/*
 * This init operation provides :
 *  - task creation
 *  - module fully initialized
 */
INIT_OP_DECLARE(task_setup);

#endif /* _KERN_TASK_H */
