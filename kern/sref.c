/*
 * Copyright (c) 2014-2017 Richard Braun.
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
 *
 *
 * This implementation is based on the paper "RadixVM: Scalable address
 * spaces for multithreaded applications" by Austin T. Clements,
 * M. Frans Kaashoek, and Nickolai Zeldovich. Specifically, it implements
 * the Refcache component described in the paper, with a few differences
 * outlined below.
 *
 * Refcache synchronizes access to delta caches by disabling preemption.
 * That behaviour is realtime-unfriendly because of the large number of
 * deltas in a cache. This module uses dedicated manager threads to
 * perform cache flushes and review queue processing, and mutexes to
 * synchronize cache access.
 *
 * In addition, Refcache normally requires all processors to regularly
 * process their local data. That behaviour is dyntick-unfriendly. As a
 * result, this module handles processor registration so that processors
 * that aren't participating in reference counting (e.g. because they're
 * idling) don't prevent others from progressing. Instead of per-processor
 * review queues, there is one global review queue which can be managed
 * from any processor. Review queue access should still be considerably
 * infrequent in practice, keeping the impact on contention low.
 *
 * Locking protocol : cache -> counter -> global data
 *
 * TODO Reconsider whether it's possible to bring back local review queues.
 */

#include <stdbool.h>
#include <stddef.h>

#include <kern/assert.h>
#include <kern/condition.h>
#include <kern/cpumap.h>
#include <kern/error.h>
#include <kern/init.h>
#include <kern/macros.h>
#include <kern/mutex.h>
#include <kern/panic.h>
#include <kern/param.h>
#include <kern/percpu.h>
#include <kern/spinlock.h>
#include <kern/sprintf.h>
#include <kern/sref.h>
#include <kern/sref_i.h>
#include <kern/syscnt.h>
#include <kern/thread.h>
#include <machine/cpu.h>

/*
 * Maximum number of deltas per cache.
 */
#define SREF_MAX_DELTAS 4096

#ifdef __LP64__
#define SREF_HASH_SHIFT 3
#else /* __LP64__ */
#define SREF_HASH_SHIFT 2
#endif /* __LP64__ */

/*
 * Number of counters in review queue beyond which to issue a warning.
 */
#define SREF_NR_COUNTERS_WARN 10000

struct sref_queue {
    struct sref_counter *first;
    struct sref_counter *last;
    unsigned long size;
};

/*
 * Global data.
 *
 * If there is a pending flush, its associated CPU must be registered.
 * Notwithstanding transient states, the number of pending flushes is 0
 * if and only if no processor is registered, in which case the sref
 * module, and probably the whole system, is completely idle.
 *
 * The review queue is implemented with two queues of counters. Each
 * queue is named with a number that matches the number of epochs that
 * occurred since their counters were added.
 */
struct sref_data {
    struct spinlock lock;
    struct cpumap registered_cpus;
    unsigned int nr_registered_cpus;
    struct cpumap pending_flushes;
    unsigned int nr_pending_flushes;
    struct sref_queue queue0;
    struct sref_queue queue1;
    struct syscnt sc_epochs;
    struct syscnt sc_dirty_zeroes;
    struct syscnt sc_revives;
    struct syscnt sc_true_zeroes;
    int no_warning;
};

/*
 * Temporary difference to apply on a reference counter.
 *
 * Deltas are stored in per-processor caches and added to their global
 * counter when flushed. A delta is valid if and only if the counter it
 * points to isn't NULL.
 *
 * On cache flush, if a delta is valid, it must be flushed whatever its
 * value because a delta can be a dirty zero too. By flushing all valid
 * deltas, and clearing them all after a flush, activity on a counter is
 * reliably reported.
 */
struct sref_delta {
    struct sref_counter *counter;
    unsigned long value;
};

/*
 * Per-processor cache of deltas.
 *
 * Delta caches are implemented with hash tables for quick ref count to
 * delta lookups. For now, a very simple replacement policy, similar to
 * that described in the RadixVM paper, is used. Improve with an LRU-like
 * algorithm if this turns out to be a problem.
 *
 * Manager threads periodically flush deltas and process the review queue.
 * Waking up a manager thread must be done with interrupts disabled to
 * prevent a race with the periodic event that drives regular flushes
 * (normally the periodic timer interrupt).
 *
 * Changing the registered flag is done with preemption disabled. The
 * periodic event handler checks whether the current processor is
 * registered, and can do so at any time. This race is harmless.
 *
 * The dirty flag means there may be data to process, and is used to wake
 * up the manager thread. Marking a cache dirty is done either by regular
 * threads increasing or decreasing a delta, or the periodic event handler.
 * Clearing the dirty flag is only done by the manager thread. The cache
 * lock makes sure only one thread is accessing the cache at any time, but
 * it doesn't prevent the periodic handler from running. Since the handler
 * as well as regular threads set that flag, a race between them is harmless.
 * On the other hand, the handler won't access the flag if it is run while
 * the manager thread is running. Since the manager thread is already running,
 * there is no need to wake it up anyway.
 */
struct sref_cache {
    struct mutex lock;
    struct sref_delta deltas[SREF_MAX_DELTAS];
    struct syscnt sc_collisions;
    struct syscnt sc_flushes;
    struct thread *manager;
    int registered;
    int dirty;
};

static struct sref_data sref_data;
static struct sref_cache sref_cache __percpu;

static void __init
sref_queue_init(struct sref_queue *queue)
{
    queue->first = NULL;
    queue->last = NULL;
    queue->size = 0;
}

static inline unsigned long
sref_queue_size(const struct sref_queue *queue)
{
    return queue->size;
}

static inline int
sref_queue_empty(const struct sref_queue *queue)
{
    return (queue->size == 0);
}

static void
sref_queue_push(struct sref_queue *queue, struct sref_counter *counter)
{
    counter->next = NULL;

    if (queue->last == NULL) {
        queue->first = counter;
    } else {
        queue->last->next = counter;
    }

    queue->last = counter;
    queue->size++;
}

static struct sref_counter *
sref_queue_pop(struct sref_queue *queue)
{
    struct sref_counter *counter;

    counter = queue->first;
    queue->first = counter->next;

    if (queue->last == counter) {
        queue->last = NULL;
    }

    queue->size--;
    return counter;
}

static void
sref_queue_transfer(struct sref_queue *dest, struct sref_queue *src)
{
    *dest = *src;
}

static void
sref_queue_concat(struct sref_queue *queue1, struct sref_queue *queue2)
{
    if (sref_queue_empty(queue2)) {
        return;
    }

    if (sref_queue_empty(queue1)) {
        sref_queue_transfer(queue1, queue2);
        return;
    }

    queue1->last->next = queue2->first;
    queue1->last = queue2->last;
    queue1->size += queue2->size;
}

static inline bool
sref_counter_aligned(const struct sref_counter *counter)
{
    return (((uintptr_t)counter & (~SREF_WEAKREF_MASK)) == 0);
}

static void
sref_weakref_init(struct sref_weakref *weakref, struct sref_counter *counter)
{
    assert(sref_counter_aligned(counter));
    weakref->addr = (uintptr_t)counter;
}

static void
sref_weakref_mark_dying(struct sref_weakref *weakref)
{
    atomic_or_uintptr(&weakref->addr, SREF_WEAKREF_DYING);
}

static void
sref_weakref_clear_dying(struct sref_weakref *weakref)
{
    atomic_and_uintptr(&weakref->addr, SREF_WEAKREF_MASK);
}

static int
sref_weakref_kill(struct sref_weakref *weakref)
{
    uintptr_t addr, oldval;

    addr = weakref->addr | SREF_WEAKREF_DYING;
    oldval = atomic_cas_uintptr(&weakref->addr, addr, (uintptr_t)NULL);

    if (oldval != addr) {
        assert((oldval & SREF_WEAKREF_MASK) == (addr & SREF_WEAKREF_MASK));
        return ERROR_BUSY;
    }

    return 0;
}

static struct sref_counter *
sref_weakref_tryget(struct sref_weakref *weakref)
{
    uintptr_t addr, oldval, newval;

    do {
        addr = weakref->addr;
        newval = addr & SREF_WEAKREF_MASK;
        oldval = atomic_cas_uintptr(&weakref->addr, addr, newval);
    } while (oldval != addr);

    return (struct sref_counter *)newval;
}

static inline uintptr_t
sref_counter_hash(const struct sref_counter *counter)
{
    uintptr_t va;

    va = (uintptr_t)counter;

    assert(P2ALIGNED(va, 1UL << SREF_HASH_SHIFT));
    return (va >> SREF_HASH_SHIFT);
}

static inline uintptr_t
sref_counter_index(const struct sref_counter *counter)
{
    return (sref_counter_hash(counter) & (SREF_MAX_DELTAS - 1));
}

static inline int
sref_counter_is_queued(const struct sref_counter *counter)
{
    return (counter->flags & SREF_QUEUED);
}

static inline void
sref_counter_mark_queued(struct sref_counter *counter)
{
    counter->flags |= SREF_QUEUED;
}

static inline void
sref_counter_clear_queued(struct sref_counter *counter)
{
    counter->flags &= ~SREF_QUEUED;
}

static inline int
sref_counter_is_dirty(const struct sref_counter *counter)
{
    return (counter->flags & SREF_DIRTY);
}

static inline void
sref_counter_mark_dirty(struct sref_counter *counter)
{
    counter->flags |= SREF_DIRTY;
}

static inline void
sref_counter_clear_dirty(struct sref_counter *counter)
{
    counter->flags &= ~SREF_DIRTY;
}

static inline void
sref_counter_mark_dying(struct sref_counter *counter)
{
    if (counter->weakref == NULL) {
        return;
    }

    sref_weakref_mark_dying(counter->weakref);
}

static inline void
sref_counter_clear_dying(struct sref_counter *counter)
{
    if (counter->weakref == NULL) {
        return;
    }

    sref_weakref_clear_dying(counter->weakref);
}

static inline int
sref_counter_kill_weakref(struct sref_counter *counter)
{
    if (counter->weakref == NULL) {
        return 0;
    }

    return sref_weakref_kill(counter->weakref);
}

static void
sref_counter_schedule_review(struct sref_counter *counter)
{
    assert(!sref_counter_is_queued(counter));
    assert(!sref_counter_is_dirty(counter));

    sref_counter_mark_queued(counter);
    sref_counter_mark_dying(counter);

    spinlock_lock(&sref_data.lock);
    sref_queue_push(&sref_data.queue0, counter);
    spinlock_unlock(&sref_data.lock);
}

static void
sref_counter_add(struct sref_counter *counter, unsigned long delta)
{
    spinlock_lock(&counter->lock);

    counter->value += delta;

    if (counter->value == 0) {
        if (sref_counter_is_queued(counter)) {
            sref_counter_mark_dirty(counter);
        } else {
            sref_counter_schedule_review(counter);
        }
    }

    spinlock_unlock(&counter->lock);
}

static void __init
sref_delta_init(struct sref_delta *delta)
{
    delta->counter = NULL;
    delta->value = 0;
}

static inline struct sref_counter *
sref_delta_counter(struct sref_delta *delta)
{
    return delta->counter;
}

static inline void
sref_delta_set_counter(struct sref_delta *delta, struct sref_counter *counter)
{
    assert(delta->value == 0);
    delta->counter = counter;
}

static inline void
sref_delta_clear(struct sref_delta *delta)
{
    assert(delta->value == 0);
    delta->counter = NULL;
}

static inline void
sref_delta_inc(struct sref_delta *delta)
{
    delta->value++;
}

static inline void
sref_delta_dec(struct sref_delta *delta)
{
    delta->value--;
}

static inline int
sref_delta_is_valid(const struct sref_delta *delta)
{
    return (delta->counter != NULL);
}

static void
sref_delta_flush(struct sref_delta *delta)
{
    sref_counter_add(delta->counter, delta->value);
    delta->value = 0;
}

static void
sref_delta_evict(struct sref_delta *delta)
{
    sref_delta_flush(delta);
    sref_delta_clear(delta);
}

static inline unsigned long
sref_review_queue_size(void)
{
    return (sref_queue_size(&sref_data.queue0)
            + sref_queue_size(&sref_data.queue1));
}

static inline int
sref_review_queue_empty(void)
{
    return (sref_review_queue_size() == 0);
}

static void
sref_reset_pending_flushes(void)
{
    cpumap_copy(&sref_data.pending_flushes, &sref_data.registered_cpus);
    sref_data.nr_pending_flushes = sref_data.nr_registered_cpus;
}

static void
sref_end_epoch(struct sref_queue *queue)
{
    assert(cpumap_find_first(&sref_data.registered_cpus) != -1);
    assert(sref_data.nr_registered_cpus != 0);
    assert(cpumap_find_first(&sref_data.pending_flushes) == -1);
    assert(sref_data.nr_pending_flushes == 0);

    if (!sref_data.no_warning
        && (sref_review_queue_size() >= SREF_NR_COUNTERS_WARN)) {
        sref_data.no_warning = 1;
        printk("sref: warning: large number of counters in review queue\n");
    }

    if (sref_data.nr_registered_cpus == 1) {
        sref_queue_concat(&sref_data.queue1, &sref_data.queue0);
        sref_queue_init(&sref_data.queue0);
    }

    sref_queue_transfer(queue, &sref_data.queue1);
    sref_queue_transfer(&sref_data.queue1, &sref_data.queue0);
    sref_queue_init(&sref_data.queue0);
    syscnt_inc(&sref_data.sc_epochs);
    sref_reset_pending_flushes();
}

static inline struct sref_delta *
sref_cache_delta(struct sref_cache *cache, unsigned long i)
{
    assert(i < ARRAY_SIZE(cache->deltas));
    return &cache->deltas[i];
}

static void __init
sref_cache_init(struct sref_cache *cache, unsigned int cpu)
{
    char name[SYSCNT_NAME_SIZE];
    struct sref_delta *delta;
    unsigned long i;

    mutex_init(&cache->lock);

    for (i = 0; i < ARRAY_SIZE(cache->deltas); i++) {
        delta = sref_cache_delta(cache, i);
        sref_delta_init(delta);
    }

    snprintf(name, sizeof(name), "sref_collisions/%u", cpu);
    syscnt_register(&cache->sc_collisions, name);
    snprintf(name, sizeof(name), "sref_flushes/%u", cpu);
    syscnt_register(&cache->sc_flushes, name);
    cache->manager = NULL;
    cache->registered = 0;
    cache->dirty = 0;
}

static inline struct sref_cache *
sref_cache_get(void)
{
    return cpu_local_ptr(sref_cache);
}

static struct sref_cache *
sref_cache_acquire(void)
{
    struct sref_cache *cache;

    thread_pin();
    cache = sref_cache_get();

    mutex_lock(&cache->lock);
    return cache;
}

static void
sref_cache_release(struct sref_cache *cache)
{
    mutex_unlock(&cache->lock);
    thread_unpin();
}

static inline int
sref_cache_is_registered(const struct sref_cache *cache)
{
    return cache->registered;
}

static inline void
sref_cache_mark_registered(struct sref_cache *cache)
{
    cache->registered = 1;
}

static inline void
sref_cache_clear_registered(struct sref_cache *cache)
{
    cache->registered = 0;
}

static inline int
sref_cache_is_dirty(const struct sref_cache *cache)
{
    return cache->dirty;
}

static inline void
sref_cache_mark_dirty(struct sref_cache *cache)
{
    cache->dirty = 1;
}

static inline void
sref_cache_clear_dirty(struct sref_cache *cache)
{
    cache->dirty = 0;
}

static struct sref_delta *
sref_cache_get_delta(struct sref_cache *cache, struct sref_counter *counter)
{
    struct sref_delta *delta;

    delta = sref_cache_delta(cache, sref_counter_index(counter));

    if (!sref_delta_is_valid(delta)) {
        sref_delta_set_counter(delta, counter);
    } else if (sref_delta_counter(delta) != counter) {
        sref_delta_flush(delta);
        sref_delta_set_counter(delta, counter);
        syscnt_inc(&cache->sc_collisions);
    }

    return delta;
}

static void
sref_cache_flush(struct sref_cache *cache, struct sref_queue *queue)
{
    struct sref_delta *delta;
    unsigned int i, cpu;

    mutex_lock(&cache->lock);

    /* TODO Consider a list of valid deltas to speed things up */
    for (i = 0; i < ARRAY_SIZE(cache->deltas); i++) {
        delta = sref_cache_delta(cache, i);

        if (sref_delta_is_valid(delta)) {
            sref_delta_evict(delta);
        }
    }

    cpu = cpu_id();

    spinlock_lock(&sref_data.lock);

    assert(sref_cache_is_registered(cache));
    assert(cpumap_test(&sref_data.registered_cpus, cpu));

    if (!cpumap_test(&sref_data.pending_flushes, cpu)) {
        sref_queue_init(queue);
    } else {
        cpumap_clear(&sref_data.pending_flushes, cpu);
        sref_data.nr_pending_flushes--;

        if (sref_data.nr_pending_flushes != 0) {
            sref_queue_init(queue);
        } else {
            sref_end_epoch(queue);
        }
    }

    spinlock_unlock(&sref_data.lock);

    sref_cache_clear_dirty(cache);
    syscnt_inc(&cache->sc_flushes);

    mutex_unlock(&cache->lock);
}

static void
sref_cache_wakeup_manager(struct sref_cache *cache)
{
    unsigned long flags;

    cpu_intr_save(&flags);
    thread_wakeup(cache->manager);
    cpu_intr_restore(flags);
}

/*
 * Force the manager thread of a cache to run.
 */
static void
sref_cache_manage(struct sref_cache *cache)
{
    sref_cache_mark_dirty(cache);
    sref_cache_wakeup_manager(cache);
}

/*
 * Check if a cache is dirty and wake up its manager thread if it is.
 *
 * Return true if the cache is dirty and requires maintenance.
 */
static int
sref_cache_check(struct sref_cache *cache)
{
    if (!sref_cache_is_dirty(cache)) {
        return 0;
    }

    sref_cache_wakeup_manager(cache);
    return 1;
}

static void
sref_noref(struct work *work)
{
    struct sref_counter *counter;

    counter = structof(work, struct sref_counter, work);
    counter->noref_fn(counter);
}

static void
sref_review(struct sref_queue *queue)
{
    int64_t nr_dirty, nr_revive, nr_true;
    struct sref_counter *counter;
    struct work_queue works;
    bool requeue;
    int error;

    nr_dirty = 0;
    nr_revive = 0;
    nr_true = 0;
    work_queue_init(&works);

    while (!sref_queue_empty(queue)) {
        counter = sref_queue_pop(queue);

        spinlock_lock(&counter->lock);

        assert(sref_counter_is_queued(counter));
        sref_counter_clear_queued(counter);

        if (counter->value != 0) {
            sref_counter_clear_dirty(counter);
            sref_counter_clear_dying(counter);
            spinlock_unlock(&counter->lock);
        } else {
            if (sref_counter_is_dirty(counter)) {
                requeue = true;
                nr_dirty++;
                sref_counter_clear_dirty(counter);
            } else {
                error = sref_counter_kill_weakref(counter);

                if (!error) {
                    requeue = false;
                } else {
                    requeue = true;
                    nr_revive++;
                }
            }

            if (requeue) {
                sref_counter_schedule_review(counter);
                spinlock_unlock(&counter->lock);
            } else {
                /*
                 * Keep in mind that the work structure shares memory with
                 * the counter data. Unlocking isn't needed here, since this
                 * counter is now really at 0, but do it for consistency.
                 */
                spinlock_unlock(&counter->lock);
                nr_true++;
                work_init(&counter->work, sref_noref);
                work_queue_push(&works, &counter->work);
            }
        }
    }

    if (work_queue_nr_works(&works) != 0) {
        work_queue_schedule(&works, 0);
    }

    if ((nr_dirty + nr_revive + nr_true) != 0) {
        spinlock_lock(&sref_data.lock);
        syscnt_add(&sref_data.sc_dirty_zeroes, nr_dirty);
        syscnt_add(&sref_data.sc_revives, nr_revive);
        syscnt_add(&sref_data.sc_true_zeroes, nr_true);
        spinlock_unlock(&sref_data.lock);
    }
}

static void
sref_manage(void *arg)
{
    struct sref_cache *cache;
    struct sref_queue queue;
    unsigned long flags;

    cache = arg;

    for (;;) {
        thread_preempt_disable();
        cpu_intr_save(&flags);

        while (!sref_cache_is_dirty(cache)) {
            thread_sleep(NULL, cache, "sref");
        }

        cpu_intr_restore(flags);
        thread_preempt_enable();

        sref_cache_flush(cache, &queue);
        sref_review(&queue);
    }

    /* Never reached */
}

void __init
sref_bootstrap(void)
{
    spinlock_init(&sref_data.lock);
    sref_queue_init(&sref_data.queue0);
    sref_queue_init(&sref_data.queue1);
    syscnt_register(&sref_data.sc_epochs, "sref_epochs");
    syscnt_register(&sref_data.sc_dirty_zeroes, "sref_dirty_zeroes");
    syscnt_register(&sref_data.sc_revives, "sref_revives");
    syscnt_register(&sref_data.sc_true_zeroes, "sref_true_zeroes");

    sref_cache_init(sref_cache_get(), 0);
}

static void __init
sref_setup_manager(struct sref_cache *cache, unsigned int cpu)
{
    char name[THREAD_NAME_SIZE];
    struct thread_attr attr;
    struct thread *manager;
    struct cpumap *cpumap;
    int error;

    error = cpumap_create(&cpumap);

    if (error) {
        panic("sref: unable to create manager thread CPU map");
    }

    cpumap_zero(cpumap);
    cpumap_set(cpumap, cpu);
    snprintf(name, sizeof(name), THREAD_KERNEL_PREFIX "sref_manage/%u", cpu);
    thread_attr_init(&attr, name);
    thread_attr_set_cpumap(&attr, cpumap);
    thread_attr_set_priority(&attr, THREAD_SCHED_FS_PRIO_MAX);
    error = thread_create(&manager, &attr, sref_manage, cache);
    cpumap_destroy(cpumap);

    if (error) {
        panic("sref: unable to create manager thread");
    }

    cache->manager = manager;
}

void __init
sref_setup(void)
{
    unsigned int i;

    for (i = 1; i < cpu_count(); i++) {
        sref_cache_init(percpu_ptr(sref_cache, i), i);
    }

    for (i = 0; i < cpu_count(); i++) {
        sref_setup_manager(percpu_ptr(sref_cache, i), i);
    }
}

void
sref_register(void)
{
    struct sref_cache *cache;
    unsigned int cpu;

    assert(!thread_preempt_enabled());

    cache = sref_cache_get();
    assert(!sref_cache_is_registered(cache));
    assert(!sref_cache_is_dirty(cache));

    cpu = cpu_id();

    spinlock_lock(&sref_data.lock);

    assert(!cpumap_test(&sref_data.registered_cpus, cpu));
    cpumap_set(&sref_data.registered_cpus, cpu);
    sref_data.nr_registered_cpus++;

    if ((sref_data.nr_registered_cpus == 1)
        && (sref_data.nr_pending_flushes == 0)) {
        assert(sref_review_queue_empty());
        sref_reset_pending_flushes();
    }

    spinlock_unlock(&sref_data.lock);

    sref_cache_mark_registered(cache);
}

int
sref_unregister(void)
{
    struct sref_cache *cache;
    unsigned int cpu;
    int dirty, error;

    assert(!thread_preempt_enabled());

    cache = sref_cache_get();
    assert(sref_cache_is_registered(cache));

    /*
     * Check the dirty flag after clearing the registered flag. The
     * periodic event handler won't set the dirty flag if the processor
     * is unregistered. It is then safe to test if that flag is set.
     * Everything involved is processor-local, therefore a simple compiler
     * barrier is enough to enforce ordering.
     */
    sref_cache_clear_registered(cache);
    barrier();
    dirty = sref_cache_check(cache);

    if (dirty) {
        sref_cache_mark_registered(cache);
        return ERROR_BUSY;
    }

    cpu = cpu_id();

    spinlock_lock(&sref_data.lock);

    assert(cpumap_test(&sref_data.registered_cpus, cpu));

    if (!cpumap_test(&sref_data.pending_flushes, cpu)) {
        assert(sref_data.nr_pending_flushes != 0);
        error = 0;
    } else if ((sref_data.nr_registered_cpus == 1)
               && (sref_data.nr_pending_flushes == 1)
               && sref_review_queue_empty()) {
        cpumap_clear(&sref_data.pending_flushes, cpu);
        sref_data.nr_pending_flushes--;
        error = 0;
    } else {
        sref_cache_manage(cache);
        error = ERROR_BUSY;
    }

    if (error) {
        sref_cache_mark_registered(cache);
    } else {
        cpumap_clear(&sref_data.registered_cpus, cpu);
        sref_data.nr_registered_cpus--;
    }

    spinlock_unlock(&sref_data.lock);

    return error;
}

void
sref_report_periodic_event(void)
{
    struct sref_cache *cache;

    assert(!cpu_intr_enabled());
    assert(!thread_preempt_enabled());

    cache = sref_cache_get();

    if (!sref_cache_is_registered(cache)
        || (cache->manager == thread_self())) {
        return;
    }

    sref_cache_manage(cache);
}

void
sref_counter_init(struct sref_counter *counter,
                  struct sref_weakref *weakref,
                  sref_noref_fn_t noref_fn)
{
    counter->noref_fn = noref_fn;
    spinlock_init(&counter->lock);
    counter->flags = 0;
    counter->value = 1;
    counter->weakref = weakref;

    if (weakref != NULL) {
        sref_weakref_init(weakref, counter);
    }
}

static void
sref_counter_inc_common(struct sref_counter *counter, struct sref_cache *cache)
{
    struct sref_delta *delta;

    sref_cache_mark_dirty(cache);
    delta = sref_cache_get_delta(cache, counter);
    sref_delta_inc(delta);
}

void
sref_counter_inc(struct sref_counter *counter)
{
    struct sref_cache *cache;

    cache = sref_cache_acquire();
    sref_counter_inc_common(counter, cache);
    sref_cache_release(cache);
}

void
sref_counter_dec(struct sref_counter *counter)
{
    struct sref_cache *cache;
    struct sref_delta *delta;

    cache = sref_cache_acquire();
    sref_cache_mark_dirty(cache);
    delta = sref_cache_get_delta(cache, counter);
    sref_delta_dec(delta);
    sref_cache_release(cache);
}

struct sref_counter *
sref_weakref_get(struct sref_weakref *weakref)
{
    struct sref_counter *counter;
    struct sref_cache *cache;

    cache = sref_cache_acquire();

    counter = sref_weakref_tryget(weakref);

    if (counter != NULL) {
        sref_counter_inc_common(counter, cache);
    }

    sref_cache_release(cache);

    return counter;
}
