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
#include <kern/spinlock.h>
#include <kern/stddef.h>
#include <kern/string.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <vm/vm_kmem.h>

/*
 * Kernel task and storage.
 */
static struct task kernel_task_store;
struct task *kernel_task = &kernel_task_store;

/*
 * Cache for allocated tasks.
 */
static struct kmem_cache task_cache;

/*
 * Global list of tasks.
 */
static struct list task_list;
static struct spinlock task_list_lock;

static void
task_init(struct task *task, const char *name, struct vm_map *map)
{
    spinlock_init(&task->lock);
    list_init(&task->threads);
    task->map = map;
    strlcpy(task->name, name, sizeof(task->name));
}

void __init
task_setup(void)
{
    kmem_cache_init(&task_cache, "task", sizeof(struct task),
                    0, NULL, NULL, NULL, 0);
    list_init(&task_list);
    spinlock_init(&task_list_lock);
    task_init(kernel_task, "x15", kernel_map);
    list_insert(&task_list, &kernel_task->node);
}

int
task_create(struct task **taskp, const char *name)
{
    struct task *task;

    task = kmem_cache_alloc(&task_cache);

    if (task == NULL)
        return ERROR_NOMEM;

    /* TODO VM map */
    task_init(task, name, NULL);

    spinlock_lock(&task_list_lock);
    list_insert(&task_list, &kernel_task->node);
    spinlock_unlock(&task_list_lock);

    *taskp = task;
    return 0;
}

void
task_add_thread(struct task *task, struct thread *thread)
{
    spinlock_lock(&task->lock);
    list_insert_tail(&task->threads, &thread->task_node);
    spinlock_unlock(&task->lock);
}

void
task_info(struct task *task)
{
    struct thread *thread;

    if (task == NULL) {
        spinlock_lock(&task_list_lock);

        list_for_each_entry(&task_list, task, node)
            printk("task: %s\n", task->name);

        spinlock_unlock(&task_list_lock);

        return;
    }

    spinlock_lock(&task->lock);

    printk("task: name: %s, threads :\n", task->name);

    list_for_each_entry(&task->threads, thread, task_node)
        printk("task: %s: %s\n", task->name, thread->name);

    spinlock_unlock(&task->lock);
}
