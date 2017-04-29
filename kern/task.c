/*
 * Copyright (c) 2012-2014 Richard Braun.
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

#include <stddef.h>
#include <string.h>

#include <kern/error.h>
#include <kern/init.h>
#include <kern/kmem.h>
#include <kern/list.h>
#include <kern/param.h>
#include <kern/spinlock.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <vm/vm_kmem.h>
#include <vm/vm_map.h>

#ifdef __LP64__
#define TASK_INFO_ADDR_FMT "%016lx"
#else /* __LP64__ */
#define TASK_INFO_ADDR_FMT "%08lx"
#endif /* __LP64__ */

/*
 * Kernel task and storage.
 */
static struct task kernel_task_store;
struct task *kernel_task __read_mostly = &kernel_task_store;

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
    kmem_cache_init(&task_cache, "task", sizeof(struct task), 0, NULL, 0);
    list_init(&task_list);
    spinlock_init(&task_list_lock);
    task_init(kernel_task, "x15", kernel_map);
    list_insert_head(&task_list, &kernel_task->node);
}

int
task_create(struct task **taskp, const char *name)
{
    struct vm_map *map;
    struct task *task;
    int error;

    task = kmem_cache_alloc(&task_cache);

    if (task == NULL) {
        error = ERROR_NOMEM;
        goto error_task;
    }

    error = vm_map_create(&map);

    if (error) {
        goto error_map;
    }

    task_init(task, name, map);

    spinlock_lock(&task_list_lock);
    list_insert_tail(&task_list, &task->node);
    spinlock_unlock(&task_list_lock);

    *taskp = task;
    return 0;

error_map:
    kmem_cache_free(&task_cache, task);
error_task:
    return error;
}

void
task_add_thread(struct task *task, struct thread *thread)
{
    spinlock_lock(&task->lock);
    list_insert_tail(&task->threads, &thread->task_node);
    spinlock_unlock(&task->lock);
}

void
task_remove_thread(struct task *task, struct thread *thread)
{
    spinlock_lock(&task->lock);
    list_remove(&thread->task_node);
    spinlock_unlock(&task->lock);
}

void
task_info(struct task *task)
{
    struct thread *thread;

    if (task == NULL) {
        spinlock_lock(&task_list_lock);

        list_for_each_entry(&task_list, task, node) {
            printf("task: %s\n", task->name);
        }

        spinlock_unlock(&task_list_lock);

        return;
    }

    spinlock_lock(&task->lock);

    printf("task: name: %s, threads:\n", task->name);

    /*
     * Don't grab any lock when accessing threads, so that the function
     * can be used to debug in the middle of most critical sections.
     * Threads are only destroyed after being removed from their task
     * so holding the task lock is enough to guarantee existence.
     */
    list_for_each_entry(&task->threads, thread, task_node) {
        printf(TASK_INFO_ADDR_FMT " %c %8s:" TASK_INFO_ADDR_FMT
               " %.2s:%02hu %02u %s\n",
               (unsigned long)thread,
               thread_state_to_chr(thread),
               thread_wchan_desc(thread),
               (unsigned long)thread_wchan_addr(thread),
               thread_sched_class_to_str(thread_user_sched_class(thread)),
               thread_user_priority(thread),
               thread_real_global_priority(thread),
               thread->name);
    }

    spinlock_unlock(&task->lock);
}
