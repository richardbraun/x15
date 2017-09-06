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

#include <assert.h>
#include <stdalign.h>
#include <stddef.h>

#include <kern/bitmap.h>
#include <kern/error.h>
#include <kern/init.h>
#include <kern/kmem.h>
#include <kern/list.h>
#include <kern/log.h>
#include <kern/macros.h>
#include <kern/panic.h>
#include <kern/percpu.h>
#include <kern/spinlock.h>
#include <kern/syscnt.h>
#include <kern/thread.h>
#include <kern/work.h>
#include <machine/cpu.h>

#define WORK_PRIO_NORMAL    THREAD_SCHED_FS_PRIO_DEFAULT
#define WORK_PRIO_HIGH      THREAD_SCHED_FS_PRIO_MAX

#define WORK_INVALID_CPU ((unsigned int)-1)

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
#define WORK_MAX_THREADS        MAX(X15_MAX_CPUS, WORK_THREADS_THRESHOLD)

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
 * Interrupts must be disabled when accessing a work pool. Holding the
 * lock is required for global pools only, whereas exclusive access on
 * per-processor pools is achieved by disabling preemption.
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
 */
struct work_pool {
    alignas(CPU_L1_SIZE) struct spinlock lock;
    int flags;
    struct work_queue queue0;
    struct work_queue queue1;
    struct work_thread *manager;
    struct syscnt sc_transfers;
    unsigned int cpu;
    unsigned int max_threads;
    unsigned int nr_threads;
    unsigned int nr_available_threads;
    struct list available_threads;
    struct list dead_threads;
    BITMAP_DECLARE(bitmap, WORK_MAX_THREADS);
};

static int work_thread_create(struct work_pool *pool, unsigned int id);
static void work_thread_destroy(struct work_thread *worker);

static struct work_pool work_pool_cpu_main __percpu;
static struct work_pool work_pool_cpu_highprio __percpu;
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
    assert(!(pool->flags & WORK_PF_GLOBAL));
    return pool->cpu;
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

static void __init
work_pool_init(struct work_pool *pool, unsigned int cpu, int flags)
{
    char name[SYSCNT_NAME_SIZE];
    const char *suffix;
    unsigned int id, nr_cpus, max_threads;
    int error;

    pool->flags = flags;

    if (flags & WORK_PF_GLOBAL) {
        nr_cpus = cpu_count();
        pool->cpu = WORK_INVALID_CPU;
    } else {
        nr_cpus = 1;
        suffix = (flags & WORK_PF_HIGHPRIO) ? "h" : "";
        snprintf(name, sizeof(name), "work_transfers/%u%s", cpu, suffix);
        syscnt_register(&pool->sc_transfers, name);
        pool->cpu = cpu;
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
    list_init(&pool->dead_threads);
    bitmap_zero(pool->bitmap, WORK_MAX_THREADS);

    id = work_pool_alloc_id(pool);
    error = work_thread_create(pool, id);

    if (error) {
        goto error_thread;
    }

    return;

error_thread:
    panic("work: unable to create initial worker thread");
}

static struct work_pool *
work_pool_cpu_select(int flags)
{
    return (flags & WORK_HIGHPRIO)
           ? cpu_local_ptr(work_pool_cpu_highprio)
           : cpu_local_ptr(work_pool_cpu_main);
}

static void
work_pool_acquire(struct work_pool *pool, unsigned long *flags)
{
    if (pool->flags & WORK_PF_GLOBAL) {
        spinlock_lock_intr_save(&pool->lock, flags);
    } else {
        thread_preempt_disable_intr_save(flags);
    }
}

static void
work_pool_release(struct work_pool *pool, unsigned long flags)
{
    if (pool->flags & WORK_PF_GLOBAL) {
        spinlock_unlock_intr_restore(&pool->lock, flags);
    } else {
        thread_preempt_enable_intr_restore(flags);
    }
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
        if (work_queue_nr_works(&pool->queue1) != 0) {
            return work_queue_pop(&pool->queue1);
        }
    }

    return work_queue_pop(&pool->queue0);
}

static void
work_pool_wakeup_manager(struct work_pool *pool)
{
    if (work_pool_nr_works(pool) == 0) {
        return;
    }

    if (pool->manager != NULL) {
        thread_wakeup(pool->manager->thread);
    }
}

static void
work_pool_shift_queues(struct work_pool *pool, struct work_queue *old_queue)
{
    assert(!(pool->flags & WORK_PF_GLOBAL));

    work_queue_transfer(old_queue, &pool->queue1);
    work_queue_transfer(&pool->queue1, &pool->queue0);
    work_queue_init(&pool->queue0);

    if (work_queue_nr_works(old_queue) != 0) {
        syscnt_inc(&pool->sc_transfers);
    }
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
    struct spinlock *lock;
    unsigned long flags;
    unsigned int id;
    int error;

    self = arg;
    pool = self->pool;
    lock = (pool->flags & WORK_PF_GLOBAL) ? &pool->lock : NULL;

    work_pool_acquire(pool, &flags);

    for (;;) {
        if (pool->manager != NULL) {
            list_insert_tail(&pool->available_threads, &self->node);
            pool->nr_available_threads++;

            do {
                thread_sleep(lock, pool, "work_spr");
            } while (pool->manager != NULL);

            list_remove(&self->node);
            pool->nr_available_threads--;
        }

        if (!list_empty(&pool->dead_threads)) {
            worker = list_first_entry(&pool->dead_threads,
                                      struct work_thread, node);
            list_remove(&worker->node);
            work_pool_release(pool, flags);

            id = worker->id;
            work_thread_destroy(worker);

            /*
             * Release worker ID last so that, if the pool is full, no new
             * worker can be created unless all the resources of the worker
             * being destroyed have been freed. This is important to enforce
             * a strict boundary on the total amount of resources allocated
             * for a pool at any time.
             */
            work_pool_acquire(pool, &flags);
            work_pool_free_id(pool, id);
            continue;
        }

        if (work_pool_nr_works(pool) == 0) {
            if (pool->nr_threads > WORK_THREADS_SPARE) {
                break;
            }

            pool->manager = self;

            do {
                thread_sleep(lock, pool, "work_mgr");
            } while (work_pool_nr_works(pool) == 0);

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
                work_pool_release(pool, flags);

                error = work_thread_create(pool, id);

                work_pool_acquire(pool, &flags);

                if (error) {
                    work_pool_free_id(pool, id);
                    log_warning("work: unable to create worker thread");
                }
            }
        }

        work_pool_release(pool, flags);

        work->fn(work);

        work_pool_acquire(pool, &flags);
    }

    list_insert_tail(&pool->dead_threads, &self->node);
    work_pool_release(pool, flags);
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

    if (worker == NULL) {
        return ERROR_NOMEM;
    }

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
        snprintf(name, sizeof(name),
                 THREAD_KERNEL_PREFIX "work_process/g:%u%s",
                 worker->id, suffix);
    } else {
        unsigned int pool_id;

        error = cpumap_create(&cpumap);

        if (error) {
            goto error_cpumap;
        }

        pool_id = work_pool_cpu_id(pool);
        cpumap_zero(cpumap);
        cpumap_set(cpumap, pool_id);
        snprintf(name, sizeof(name),
                 THREAD_KERNEL_PREFIX "work_process/%u:%u%s",
                 pool_id, worker->id, suffix);
    }

    thread_attr_init(&attr, name);
    thread_attr_set_priority(&attr, priority);

    if (cpumap != NULL) {
        thread_attr_set_cpumap(&attr, cpumap);
    }

    error = thread_create(&worker->thread, &attr, work_process, worker);

    if (cpumap != NULL) {
        cpumap_destroy(cpumap);
    }

    if (error) {
        goto error_thread;
    }

    return 0;

error_thread:
error_cpumap:
    kmem_cache_free(&work_thread_cache, worker);
    return error;
}

static void
work_thread_destroy(struct work_thread *worker)
{
    thread_join(worker->thread);
    kmem_cache_free(&work_thread_cache, worker);
}

static int __init
work_setup(void)
{
    unsigned int i;

    kmem_cache_init(&work_thread_cache, "work_thread",
                    sizeof(struct work_thread), 0, NULL, 0);

    for (i = 0; i < cpu_count(); i++) {
        work_pool_init(percpu_ptr(work_pool_cpu_main, i), i, 0);
        work_pool_init(percpu_ptr(work_pool_cpu_highprio, i), i,
                       WORK_PF_HIGHPRIO);
    }

    work_pool_init(&work_pool_main, WORK_INVALID_CPU, WORK_PF_GLOBAL);
    work_pool_init(&work_pool_highprio, WORK_INVALID_CPU,
                   WORK_PF_GLOBAL | WORK_PF_HIGHPRIO);

    log_info("work: threads per pool (per-cpu/global): %u/%u, spare: %u",
             percpu_var(work_pool_cpu_main.max_threads, 0),
             work_pool_main.max_threads, WORK_THREADS_SPARE);

    return 0;
}

INIT_OP_DEFINE(work_setup,
               INIT_OP_DEP(cpu_mp_probe, true),
               INIT_OP_DEP(kmem_setup, true),
               INIT_OP_DEP(log_setup, true),
               INIT_OP_DEP(panic_setup, true),
               INIT_OP_DEP(spinlock_setup, true),
               INIT_OP_DEP(syscnt_setup, true),
               INIT_OP_DEP(thread_bootstrap, true));

void
work_schedule(struct work *work, int flags)
{
    struct work_pool *pool;
    unsigned long cpu_flags;

    thread_pin();
    pool = work_pool_cpu_select(flags);
    work_pool_acquire(pool, &cpu_flags);
    work_pool_push_work(pool, work);
    work_pool_release(pool, cpu_flags);
    thread_unpin();
}

void
work_queue_schedule(struct work_queue *queue, int flags)
{
    struct work_pool *pool;
    unsigned long cpu_flags;

    thread_pin();
    pool = work_pool_cpu_select(flags);
    work_pool_acquire(pool, &cpu_flags);
    work_pool_concat_queue(pool, queue);
    work_pool_release(pool, cpu_flags);
    thread_unpin();
}

void
work_report_periodic_event(void)
{
    struct work_queue queue, highprio_queue;

    assert(thread_check_intr_context());

    work_pool_shift_queues(cpu_local_ptr(work_pool_cpu_main), &queue);
    work_pool_shift_queues(cpu_local_ptr(work_pool_cpu_highprio),
                           &highprio_queue);

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
