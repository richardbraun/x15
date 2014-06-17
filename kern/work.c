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
#include <kern/evcnt.h>
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

/*
 * Work pool flags.
 */
#define WORK_PF_GLOBAL      0x1 /* System-wide work queue */
#define WORK_PF_HIGHPRIO    0x2 /* High priority worker threads */

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
 *
 * There are two internal queues of pending works. When first scheduling
 * a work, it is inserted into queue0. After a periodic event, works still
 * present in queue0 are moved to queue1. If these works are still present
 * in queue1 at the next periodic event, it means they couldn't be processed
 * for a complete period between two periodic events, at which point it is
 * assumed that processing works on the same processor they were queued on
 * becomes less relevant. As a result, periodic events also trigger the
 * transfer of works from queue1 to the matching global pool. Global pools
 * only use one queue.
 *
 * TODO While it's not strictly necessary to hold the lock when accessing a
 * per-processor pool, since disabling interrupts and preemption could be
 * used instead, it's currently enforced by the programming model of the
 * thread module. The thread_sleep() function could be changed to accept a
 * NULL interlock but this requires clearly defining constraints for safe
 * usage.
 */
struct work_pool {
    struct spinlock lock;
    int flags;
    struct work_queue queue0;
    struct work_queue queue1;
    struct work_thread *manager;
    struct evcnt ev_transfer;
    unsigned int max_threads;
    unsigned int nr_threads;
    unsigned int nr_available_threads;
    struct list available_threads;
    BITMAP_DECLARE(bitmap, WORK_MAX_THREADS);
} __aligned(CPU_L1_SIZE);

static int work_thread_create(struct work_pool *pool, unsigned int id);
static void work_thread_destroy(struct work_thread *worker);

static struct work_pool work_pool_cpu_main[MAX_CPUS];
static struct work_pool work_pool_cpu_highprio[MAX_CPUS];
static struct work_pool work_pool_main;
static struct work_pool work_pool_highprio;

static struct kmem_cache work_thread_cache;

static unsigned int
work_pool_alloc_id(struct work_pool *pool)
{
    int bit;

    assert(pool->nr_threads < pool->max_threads);
    pool->nr_threads++;
    bit = bitmap_find_first_zero(pool->bitmap, pool->max_threads);
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

static unsigned int
work_pool_cpu_id(const struct work_pool *pool)
{
    const struct work_pool *array;

    assert(!(pool->flags & WORK_PF_GLOBAL));

    array = (pool->flags & WORK_PF_HIGHPRIO)
            ? work_pool_cpu_highprio
            : work_pool_cpu_main;
    return pool - array;
}

static unsigned int
work_pool_compute_max_threads(unsigned int nr_cpus)
{
    unsigned int max_threads, ratio;

    ratio = WORK_THREADS_RATIO;
    max_threads = nr_cpus * ratio;

    while ((ratio > 1) && (max_threads > WORK_THREADS_THRESHOLD)) {
        ratio--;
        max_threads = nr_cpus * ratio;
    }

    assert(max_threads != 0);
    assert(max_threads <= WORK_MAX_THREADS);
    return max_threads;
}

static void
work_pool_init(struct work_pool *pool, int flags)
{
    char name[EVCNT_NAME_SIZE];
    const char *suffix;
    unsigned int id, nr_cpus, pool_id, max_threads;
    int error;

    pool->flags = flags;

    if (flags & WORK_PF_GLOBAL)
        nr_cpus = cpu_count();
    else {
        nr_cpus = 1;
        suffix = (flags & WORK_PF_HIGHPRIO) ? "h" : "";
        pool_id = work_pool_cpu_id(pool);
        snprintf(name, sizeof(name), "work_transfer/%u%s", pool_id, suffix);
        evcnt_register(&pool->ev_transfer, name);
    }

    max_threads = work_pool_compute_max_threads(nr_cpus);

    spinlock_init(&pool->lock);
    work_queue_init(&pool->queue0);
    work_queue_init(&pool->queue1);
    pool->manager = NULL;
    pool->max_threads = max_threads;
    pool->nr_threads = 0;
    pool->nr_available_threads = 0;
    list_init(&pool->available_threads);
    bitmap_zero(pool->bitmap, WORK_MAX_THREADS);

    id = work_pool_alloc_id(pool);
    error = work_thread_create(pool, id);

    if (error)
        goto error_thread;

    return;

error_thread:
    panic("work: unable to create initial worker thread");
}

static struct work_pool *
work_pool_cpu_select(int flags)
{
    unsigned int cpu;

    cpu = cpu_id();
    return (flags & WORK_HIGHPRIO)
           ? &work_pool_cpu_highprio[cpu]
           : &work_pool_cpu_main[cpu];
}

static int
work_pool_nr_works(const struct work_pool *pool)
{
    return (work_queue_nr_works(&pool->queue0)
            + work_queue_nr_works(&pool->queue1));
}

static struct work *
work_pool_pop_work(struct work_pool *pool)
{
    if (!(pool->flags & WORK_PF_GLOBAL)) {
        if (work_queue_nr_works(&pool->queue1) != 0)
            return work_queue_pop(&pool->queue1);
    }

    return work_queue_pop(&pool->queue0);
}

static void
work_pool_wakeup_manager(struct work_pool *pool)
{
    if (work_pool_nr_works(pool) == 0)
        return;

    if ((pool->manager != NULL) && (pool->manager->thread != thread_self()))
        thread_wakeup(pool->manager->thread);
}

static void
work_pool_shift_queues(struct work_pool *pool, struct work_queue *old_queue)
{
    assert(!(pool->flags & WORK_PF_GLOBAL));

    work_queue_transfer(old_queue, &pool->queue1);
    work_queue_transfer(&pool->queue1, &pool->queue0);
    work_queue_init(&pool->queue0);

    if (work_queue_nr_works(old_queue) != 0)
        evcnt_inc(&pool->ev_transfer);
}

static void
work_pool_push_work(struct work_pool *pool, struct work *work)
{
    work_queue_push(&pool->queue0, work);
    work_pool_wakeup_manager(pool);
}

static void
work_pool_concat_queue(struct work_pool *pool, struct work_queue *queue)
{
    work_queue_concat(&pool->queue0, queue);
    work_pool_wakeup_manager(pool);
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

        if (work_pool_nr_works(pool) == 0) {
            if (pool->nr_threads > WORK_THREADS_SPARE)
                break;

            pool->manager = self;

            do
                thread_sleep(&pool->lock);
            while (work_pool_nr_works(pool) == 0);

            pool->manager = NULL;
        }

        work = work_pool_pop_work(pool);

        if (work_pool_nr_works(pool) != 0) {
            if (pool->nr_available_threads != 0) {
                worker = list_first_entry(&pool->available_threads,
                                          struct work_thread, node);
                thread_wakeup(worker->thread);
            } else if (pool->nr_threads < pool->max_threads) {
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
    struct cpumap *cpumap;
    struct work_thread *worker;
    const char *suffix;
    unsigned short priority;
    int error;

    worker = kmem_cache_alloc(&work_thread_cache);

    if (worker == NULL)
        return ERROR_NOMEM;

    worker->pool = pool;
    worker->id = id;

    if (pool->flags & WORK_PF_HIGHPRIO) {
        suffix = "h";
        priority = WORK_PRIO_HIGH;
    } else {
        suffix = "";
        priority = WORK_PRIO_NORMAL;
    }

    if (pool->flags & WORK_PF_GLOBAL) {
        cpumap = NULL;
        snprintf(name, sizeof(name), "x15_work_process/g:%u%s",
                 worker->id, suffix);
    } else {
        unsigned int pool_id;

        error = cpumap_create(&cpumap);

        if (error)
            goto error_cpumap;

        pool_id = work_pool_cpu_id(pool);
        cpumap_zero(cpumap);
        cpumap_set(cpumap, pool_id);
        snprintf(name, sizeof(name), "x15_work_process/%u:%u%s",
                 pool_id, worker->id, suffix);
    }

    thread_attr_init(&attr, name);
    thread_attr_set_priority(&attr, priority);

    if (cpumap != NULL)
        thread_attr_set_cpumap(&attr, cpumap);

    error = thread_create(&worker->thread, &attr, work_process, worker);

    if (cpumap != NULL)
        cpumap_destroy(cpumap);

    if (error)
        goto error_thread;

    return 0;

error_thread:
error_cpumap:
    kmem_cache_free(&work_thread_cache, worker);
    return error;
}

static void
work_thread_destroy(struct work_thread *worker)
{
    kmem_cache_free(&work_thread_cache, worker);
}

void
work_setup(void)
{
    unsigned int i;

    kmem_cache_init(&work_thread_cache, "work_thread",
                    sizeof(struct work_thread), 0, NULL, NULL, NULL, 0);

    for (i = 0; i < cpu_count(); i++) {
        work_pool_init(&work_pool_cpu_main[i], 0);
        work_pool_init(&work_pool_cpu_highprio[i], WORK_PF_HIGHPRIO);
    }

    work_pool_init(&work_pool_main, WORK_PF_GLOBAL);
    work_pool_init(&work_pool_highprio, WORK_PF_GLOBAL | WORK_PF_HIGHPRIO);

    printk("work: threads per pool (per-cpu/global): %u/%u, spare: %u\n",
           work_pool_cpu_main[0].max_threads, work_pool_main.max_threads,
           WORK_THREADS_SPARE);
}

void
work_schedule(struct work *work, int flags)
{
    struct work_pool *pool;
    unsigned long lock_flags;

    thread_pin();
    pool = work_pool_cpu_select(flags);
    spinlock_lock_intr_save(&pool->lock, &lock_flags);
    work_pool_push_work(pool, work);
    spinlock_unlock_intr_restore(&pool->lock, lock_flags);
    thread_unpin();
}

void
work_queue_schedule(struct work_queue *queue, int flags)
{
    struct work_pool *pool;
    unsigned long lock_flags;

    thread_pin();
    pool = work_pool_cpu_select(flags);
    spinlock_lock_intr_save(&pool->lock, &lock_flags);
    work_pool_concat_queue(pool, queue);
    spinlock_unlock_intr_restore(&pool->lock, lock_flags);
    thread_unpin();
}

void
work_report_periodic_event(void)
{
    struct work_queue queue, highprio_queue;
    unsigned int cpu;

    assert(!cpu_intr_enabled());
    assert(!thread_preempt_enabled());

    cpu = cpu_id();

    spinlock_lock(&work_pool_cpu_main[cpu].lock);
    work_pool_shift_queues(&work_pool_cpu_main[cpu], &queue);
    spinlock_unlock(&work_pool_cpu_main[cpu].lock);

    spinlock_lock(&work_pool_cpu_highprio[cpu].lock);
    work_pool_shift_queues(&work_pool_cpu_highprio[cpu], &highprio_queue);
    spinlock_unlock(&work_pool_cpu_highprio[cpu].lock);

    if (work_queue_nr_works(&queue) != 0) {
        spinlock_lock(&work_pool_main.lock);
        work_pool_concat_queue(&work_pool_main, &queue);
        spinlock_unlock(&work_pool_main.lock);
    }

    if (work_queue_nr_works(&highprio_queue) != 0) {
        spinlock_lock(&work_pool_highprio.lock);
        work_pool_concat_queue(&work_pool_highprio, &highprio_queue);
        spinlock_unlock(&work_pool_highprio.lock);
    }
}
