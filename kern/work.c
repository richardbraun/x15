/*
 * Copyright (c) 2013-2014 Richard Braun.
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
#include <kern/bitmap.h>
#include <kern/error.h>
#include <kern/kmem.h>
#include <kern/list.h>
#include <kern/macros.h>
#include <kern/panic.h>
#include <kern/param.h>
#include <kern/printk.h>
#include <kern/spinlock.h>
#include <kern/sprintf.h>
#include <kern/stddef.h>
#include <kern/thread.h>
#include <kern/work.h>
#include <machine/cpu.h>

#define WORK_PRIO_NORMAL    THREAD_SCHED_TS_PRIO_DEFAULT
#define WORK_PRIO_HIGH      THREAD_SCHED_TS_PRIO_MAX

/*
 * Keep at least that many threads alive when a work pool is idle.
 */
#define WORK_THREADS_SPARE 4

/*
 * When computing the maximum number of worker threads, start with multiplying
 * the number of processors by the ratio below. If the result is greater than
 * the threshold, retry by decreasing the ratio until either the result is
 * less than the threshold or the ratio is 1.
 */
#define WORK_THREADS_RATIO      4
#define WORK_THREADS_THRESHOLD  512
#define WORK_MAX_THREADS        MAX(MAX_CPUS, WORK_THREADS_THRESHOLD)

#define WORK_NAME_SIZE 16

/*
 * Work pool flags.
 */
#define WORK_PF_HIGHPRIO    0x1 /* High priority worker threads */

struct work_thread {
    struct list node;
    struct thread *thread;
    struct work_pool *pool;
    unsigned int id;
};

/*
 * Pool of threads and works.
 *
 * Interrupts must be disabled when acquiring the pool lock.
 */
struct work_pool {
    struct spinlock lock;
    int flags;
    struct work_queue queue;
    struct work_thread *manager;
    unsigned int nr_threads;
    unsigned int nr_available_threads;
    struct list available_threads;
    BITMAP_DECLARE(bitmap, WORK_MAX_THREADS);
    char name[WORK_NAME_SIZE];
};

static int work_thread_create(struct work_pool *pool, unsigned int id);
static void work_thread_destroy(struct work_thread *worker);

static struct work_pool work_pool_main;
static struct work_pool work_pool_highprio;

static struct kmem_cache work_thread_cache;

static unsigned int work_max_threads __read_mostly;

static unsigned int
work_pool_alloc_id(struct work_pool *pool)
{
    int bit;

    assert(pool->nr_threads < work_max_threads);
    pool->nr_threads++;
    bit = bitmap_find_first_zero(pool->bitmap, work_max_threads);
    assert(bit >= 0);
    bitmap_set(pool->bitmap, bit);
    return bit;
}

static void
work_pool_free_id(struct work_pool *pool, unsigned int id)
{
    assert(pool->nr_threads != 0);
    pool->nr_threads--;
    bitmap_clear(pool->bitmap, id);
}

static void
work_pool_init(struct work_pool *pool, const char *name, int flags)
{
    unsigned int id;
    int error;

    spinlock_init(&pool->lock);
    pool->flags = flags;
    work_queue_init(&pool->queue);
    pool->manager = NULL;
    pool->nr_threads = 0;
    pool->nr_available_threads = 0;
    list_init(&pool->available_threads);
    bitmap_zero(pool->bitmap, work_max_threads);
    strlcpy(pool->name, name, sizeof(pool->name));

    id = work_pool_alloc_id(pool);
    error = work_thread_create(pool, id);

    if (error)
        goto error_thread;

    return;

error_thread:
    panic("work: unable to create initial worker thread");
}

static void
work_pool_wakeup_manager(struct work_pool *pool)
{
    if (pool->queue.nr_works == 0)
        return;

    if ((pool->manager != NULL) && (pool->manager->thread != thread_self()))
        thread_wakeup(pool->manager->thread);
}

static inline struct work_pool *
work_pool_select(int flags)
{
    return (flags & WORK_HIGHPRIO) ? &work_pool_highprio : &work_pool_main;
}

static void
work_process(void *arg)
{
    struct work_thread *self, *worker;
    struct work_pool *pool;
    struct work *work;
    unsigned long flags;
    unsigned int id;
    int error;

    self = arg;
    pool = self->pool;

    for (;;) {
        spinlock_lock_intr_save(&pool->lock, &flags);

        if (pool->manager != NULL) {
            list_insert_tail(&pool->available_threads, &self->node);
            pool->nr_available_threads++;

            do
                thread_sleep(&pool->lock);
            while (pool->manager != NULL);

            list_remove(&self->node);
            pool->nr_available_threads--;
        }

        if (pool->queue.nr_works == 0) {
            if (pool->nr_threads > WORK_THREADS_SPARE)
                break;

            pool->manager = self;

            do
                thread_sleep(&pool->lock);
            while (pool->queue.nr_works == 0);

            pool->manager = NULL;
        }

        work = work_queue_pop(&pool->queue);

        if (pool->queue.nr_works != 0) {
            if (pool->nr_available_threads != 0) {
                worker = list_first_entry(&pool->available_threads,
                                          struct work_thread, node);
                thread_wakeup(worker->thread);
            } else if (pool->nr_threads < work_max_threads) {
                id = work_pool_alloc_id(pool);
                spinlock_unlock_intr_restore(&pool->lock, flags);

                error = work_thread_create(pool, id);

                spinlock_lock_intr_save(&pool->lock, &flags);

                if (error) {
                    work_pool_free_id(pool, id);
                    printk("work: warning: unable to create worker thread\n");
                }
            }
        }

        spinlock_unlock_intr_restore(&pool->lock, flags);

        work->fn(work);
    }

    work_pool_free_id(pool, self->id);
    spinlock_unlock_intr_restore(&pool->lock, flags);

    work_thread_destroy(self);
}

static int
work_thread_create(struct work_pool *pool, unsigned int id)
{
    char name[THREAD_NAME_SIZE];
    struct thread_attr attr;
    struct work_thread *worker;
    unsigned short priority;
    int error;

    worker = kmem_cache_alloc(&work_thread_cache);

    if (worker == NULL)
        return ERROR_NOMEM;

    worker->pool = pool;
    worker->id = id;

    snprintf(name, sizeof(name), "x15_work_process:%s:%u", pool->name,
             worker->id);
    priority = (pool->flags & WORK_PF_HIGHPRIO)
               ? WORK_PRIO_HIGH
               : WORK_PRIO_NORMAL;
    thread_attr_init(&attr, name);
    thread_attr_set_priority(&attr, priority);
    error = thread_create(&worker->thread, &attr, work_process, worker);

    if (error)
        goto error_thread;

    return 0;

error_thread:
    kmem_cache_free(&work_thread_cache, worker);
    return error;
}

static void
work_thread_destroy(struct work_thread *worker)
{
    kmem_cache_free(&work_thread_cache, worker);
}

static void
work_compute_max_threads(void)
{
    unsigned int max_threads, nr_cpus, ratio;

    nr_cpus = cpu_count();
    ratio = WORK_THREADS_RATIO;
    max_threads = nr_cpus * ratio;

    while ((ratio > 1) && (max_threads > WORK_THREADS_THRESHOLD)) {
        ratio--;
        max_threads = nr_cpus * ratio;
    }

    assert(max_threads <= WORK_MAX_THREADS);
    work_max_threads = max_threads;
    printk("work: threads per pool (spare/limit): %u/%u\n",
           WORK_THREADS_SPARE, max_threads);
}

void
work_setup(void)
{
    kmem_cache_init(&work_thread_cache, "work_thread",
                    sizeof(struct work_thread), 0, NULL, NULL, NULL, 0);

    work_compute_max_threads();

    work_pool_init(&work_pool_main, "main", 0);
    work_pool_init(&work_pool_highprio, "highprio", WORK_PF_HIGHPRIO);
}

void
work_schedule(struct work *work, int flags)
{
    struct work_pool *pool;
    unsigned long lock_flags;

    pool = work_pool_select(flags);

    spinlock_lock_intr_save(&pool->lock, &lock_flags);
    work_queue_push(&pool->queue, work);
    work_pool_wakeup_manager(pool);
    spinlock_unlock_intr_restore(&pool->lock, lock_flags);
}

void
work_queue_schedule(struct work_queue *queue, int flags)
{
    struct work_pool *pool;
    unsigned long lock_flags;

    pool = work_pool_select(flags);

    spinlock_lock_intr_save(&pool->lock, &lock_flags);
    work_queue_concat(&pool->queue, queue);
    work_pool_wakeup_manager(pool);
    spinlock_unlock_intr_restore(&pool->lock, lock_flags);
}
