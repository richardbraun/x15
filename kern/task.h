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

#ifndef _KERN_TASK_H
#define _KERN_TASK_H

#include <kern/list.h>

/*
 * Forward declaration.
 */
struct thread;

/*
 * Task name buffer size.
 */
#define TASK_NAME_SIZE 32

/*
 * Task structure.
 */
struct task {
    struct list node;
    struct list threads;
    struct vm_map *map;
    char name[TASK_NAME_SIZE];
};

/*
 * The kernel task.
 */
extern struct task *kernel_task;

/*
 * Initialize the task module.
 */
void task_setup(void);

/*
 * Add a thread to a task.
 */
void task_add_thread(struct task *task, struct thread *thread);

#endif /* _KERN_TASK_H */
