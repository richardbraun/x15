/*
 * Copyright (c) 2014-2019 Richard Braun.
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
 * Refcache flushes delta caches directly from an interrupt handler, and
 * disables interrupts and preemption on cache access. That behavior is
 * realtime-unfriendly because of the potentially large number of deltas
 * in a cache. This module uses dedicated manager threads to perform
 * cache flushes and queue reviews, and only disables preemption on
 * individual delta access.
 *
 * Locking protocol : cache -> counter -> global data
 */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <kern/atomic.h>
#include <kern/clock.h>
#include <kern/cpumap.h>
#include <kern/init.h>
#include <kern/list.h>
#include <kern/log.h>
#include <kern/macros.h>
#include <kern/panic.h>
#include <kern/percpu.h>
#include <kern/slist.h>
#include <kern/spinlock.h>
#include <kern/sref.h>
#include <kern/sref_i.h>
#include <kern/syscnt.h>
#include <kern/thread.h>
#include <machine/cpu.h>

/*
 * Delay (in milliseconds) until a new global epoch starts.
 */
#define SREF_EPOCH_START_DELAY 10

/*
 * Per-cache delta table size.
 */
#define SREF_CACHE_DELTA_TABLE_SIZE 4096

#if !ISP2(SREF_CACHE_DELTA_TABLE_SIZE)
#error "delta table size must be a power-of-two"
#endif

#ifdef __LP64__
#define SREF_HASH_SHIFT 3
#else
#define SREF_HASH_SHIFT 2
#endif

/*
 * Negative close to 0 so that an overflow occurs early.
 */
#define SREF_EPOCH_ID_INIT_VALUE ((unsigned int)-500)

/*
 * Since review queues are processor-local, at least two local epochs
 * must have passed before a zero is considered a true zero. As a result,
 * three queues are required, one for the current epoch, and two more.
 * The queues are stored in an array used as a ring buffer that moves
 * forward with each new local epoch. Indexing in this array is done
 * with a binary mask instead of a modulo, for performance reasons, and
 * consequently, the array size must be at least the nearest power-of-two
 * above three.
 */
#define SREF_NR_QUEUES P2ROUND(3, 2)

/*
 * Number of counters in review queue beyond which to issue a warning.
 */
#define SREF_NR_COUNTERS_WARN 10000

/*
 * Global data.
 *
 * Processors regularly check the global epoch ID against their own,
 * locally cached epoch ID. If they're the same, a processor flushes
 * its cached deltas, acknowledges its flush by decrementing the number
 * of pending acknowledgment counter, and increments its local epoch ID,
 * preventing additional flushes during the same epoch.
 *
 * The last processor to acknowledge starts the next epoch.
 *
 * The epoch ID and the pending acknowledgments counter fill an entire
 * cache line each in order to avoid false sharing on SMP. Whenever
 * multiple processors may access them, they must use atomic operations
 * to avoid data races.
 *
 * Atomic operations on the pending acknowledgments counter are done
 * with acquire-release ordering to enforce the memory ordering
 * guarantees required by both the implementation and the interface.
 */
struct sref_data {
    struct {
        alignas(CPU_L1_SIZE) unsigned int epoch_id;
    };

    struct {
        alignas(CPU_L1_SIZE) unsigned int nr_pending_acks;
    };

    uint64_t start_ts;
    struct syscnt sc_epochs;
    struct syscnt sc_dirty_zeroes;
    struct syscnt sc_true_zeroes;
    struct syscnt sc_revives;
    struct syscnt sc_last_epoch_ms;
    struct syscnt sc_longest_epoch_ms;
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
    struct list node;
    struct sref_counter *counter;
    unsigned long value;
};

struct sref_queue {
    struct slist counters;
    unsigned long size;
};

/*
 * Per-processor cache of deltas.
 *
 * A cache is dirty if there is at least one delta that requires flushing.
 * It may only be flushed once per epoch.
 *
 * Delta caches are implemented with hash tables for quick ref count to
 * delta lookups. For now, a very simple replacement policy, similar to
 * that described in the RadixVM paper, is used. Improve with an LRU-like
 * algorithm if this turns out to be a problem.
 *
 * Periodic events (normally the system timer tick) trigger cache checks.
 * A cache check may wake up the manager thread if the cache needs management,
 * i.e. if it's dirty or if there are counters to review. Otherwise, the
 * flush acknowledgment is done directly to avoid the cost of a thread
 * wake-up.
 *
 * Interrupts and preemption must be disabled when accessing a delta cache.
 */
struct sref_cache {
    struct sref_data *data;
    bool dirty;
    bool flushed;
    unsigned int epoch_id;
    struct sref_delta deltas[SREF_CACHE_DELTA_TABLE_SIZE];
    struct list valid_deltas;
    struct sref_queue queues[SREF_NR_QUEUES];
    struct thread *manager;
    struct syscnt sc_collisions;
    struct syscnt sc_flushes;
};

static struct sref_data sref_data;
static struct sref_cache sref_cache __percpu;

static unsigned int
sref_data_get_epoch_id(const struct sref_data *data)
{
    return data->epoch_id;
}

static bool
sref_data_check_epoch_id(const struct sref_data *data, unsigned int epoch_id)
{
    unsigned int global_epoch_id;

    global_epoch_id = atomic_load(&data->epoch_id, ATOMIC_RELAXED);

    if (unlikely(global_epoch_id == epoch_id)) {
        atomic_fence(ATOMIC_ACQUIRE);
        return true;
    }

    return false;
}

static void
sref_data_start_epoch(struct sref_data *data)
{
    uint64_t now, duration;
    unsigned int epoch_id;

    now = clock_get_time();
    duration = clock_ticks_to_ms(now - data->start_ts);
    syscnt_set(&data->sc_last_epoch_ms, duration);

    if (duration > syscnt_read(&data->sc_longest_epoch_ms)) {
        syscnt_set(&data->sc_longest_epoch_ms, duration);
    }

    assert(data->nr_pending_acks == 0);
    data->nr_pending_acks = cpu_count();
    data->start_ts = now;

    epoch_id = atomic_load(&data->epoch_id, ATOMIC_RELAXED);
    atomic_store(&data->epoch_id, epoch_id + 1, ATOMIC_RELEASE);
}

static void
sref_data_ack_cpu(struct sref_data *data)
{
    unsigned int prev;

    prev = atomic_fetch_sub(&data->nr_pending_acks, 1, ATOMIC_ACQ_REL);

    if (prev != 1) {
        assert(prev != 0);
        return;
    }

    syscnt_inc(&data->sc_epochs);
    sref_data_start_epoch(data);
}

static void
sref_data_update_stats(struct sref_data *data, int64_t nr_dirty_zeroes,
                       int64_t nr_true_zeroes, int64_t nr_revives)
{
    syscnt_add(&data->sc_dirty_zeroes, nr_dirty_zeroes);
    syscnt_add(&data->sc_true_zeroes, nr_true_zeroes);
    syscnt_add(&data->sc_revives, nr_revives);
}

static bool
sref_counter_aligned(const struct sref_counter *counter)
{
    return ((uintptr_t)counter & (~SREF_WEAKREF_MASK)) == 0;
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
    atomic_or(&weakref->addr, SREF_WEAKREF_DYING, ATOMIC_RELAXED);
}

static void
sref_weakref_clear_dying(struct sref_weakref *weakref)
{
    atomic_and(&weakref->addr, SREF_WEAKREF_MASK, ATOMIC_RELAXED);
}

static int
sref_weakref_kill(struct sref_weakref *weakref)
{
    uintptr_t addr, oldval;

    addr = atomic_load(&weakref->addr, ATOMIC_RELAXED) | SREF_WEAKREF_DYING;
    oldval = atomic_cas(&weakref->addr, addr, (uintptr_t)NULL, ATOMIC_RELAXED);

    if (oldval != addr) {
        assert((oldval & SREF_WEAKREF_MASK) == (addr & SREF_WEAKREF_MASK));
        return EBUSY;
    }

    return 0;
}

static struct sref_counter *
sref_weakref_tryget(struct sref_weakref *weakref)
{
    uintptr_t addr, oldval, newval;

    do {
        addr = atomic_load(&weakref->addr, ATOMIC_RELAXED);
        newval = addr & SREF_WEAKREF_MASK;
        oldval = atomic_cas(&weakref->addr, addr, newval, ATOMIC_RELAXED);
    } while (oldval != addr);

    return (struct sref_counter *)newval;
}

static uintptr_t
sref_counter_hash(const struct sref_counter *counter)
{
    uintptr_t va;

    va = (uintptr_t)counter;

    assert(P2ALIGNED(va, 1UL << SREF_HASH_SHIFT));
    return va >> SREF_HASH_SHIFT;
}

static bool
sref_counter_is_queued(const struct sref_counter *counter)
{
    return counter->flags & SREF_CNTF_QUEUED;
}

static void
sref_counter_mark_queued(struct sref_counter *counter)
{
    counter->flags |= SREF_CNTF_QUEUED;
}

static void
sref_counter_clear_queued(struct sref_counter *counter)
{
    counter->flags &= ~SREF_CNTF_QUEUED;
}

static bool
sref_counter_is_dirty(const struct sref_counter *counter)
{
    return counter->flags & SREF_CNTF_DIRTY;
}

static void
sref_counter_mark_dirty(struct sref_counter *counter)
{
    counter->flags |= SREF_CNTF_DIRTY;
}

static void
sref_counter_clear_dirty(struct sref_counter *counter)
{
    counter->flags &= ~SREF_CNTF_DIRTY;
}

#ifdef SREF_VERIFY

static bool
sref_counter_is_unreferenced(const struct sref_counter *counter)
{
    return counter->flags & SREF_CNTF_UNREF;
}

static void
sref_counter_mark_unreferenced(struct sref_counter *counter)
{
    counter->flags |= SREF_CNTF_UNREF;
}

#endif /* SREF_VERIFY */

static void
sref_counter_mark_dying(struct sref_counter *counter)
{
    if (counter->weakref == NULL) {
        return;
    }

    sref_weakref_mark_dying(counter->weakref);
}

static void
sref_counter_clear_dying(struct sref_counter *counter)
{
    if (counter->weakref == NULL) {
        return;
    }

    sref_weakref_clear_dying(counter->weakref);
}

static int
sref_counter_kill_weakref(struct sref_counter *counter)
{
    if (counter->weakref == NULL) {
        return 0;
    }

    return sref_weakref_kill(counter->weakref);
}

static void __init
sref_queue_init(struct sref_queue *queue)
{
    slist_init(&queue->counters);
    queue->size = 0;
}

static bool
sref_queue_empty(const struct sref_queue *queue)
{
    return queue->size == 0;
}

static void
sref_queue_push(struct sref_queue *queue, struct sref_counter *counter)
{
    slist_insert_tail(&queue->counters, &counter->node);
    queue->size++;
}

static struct sref_counter *
sref_queue_pop(struct sref_queue *queue)
{
    struct sref_counter *counter;

    counter = slist_first_entry(&queue->counters, typeof(*counter), node);
    slist_remove(&queue->counters, NULL);
    queue->size--;
    return counter;
}

static void
sref_queue_move(struct sref_queue *dest, const struct sref_queue *src)
{
    slist_set_head(&dest->counters, &src->counters);
    dest->size = src->size;
}

static struct sref_queue *
sref_cache_get_queue(struct sref_cache *cache, size_t index)
{
    assert(index < ARRAY_SIZE(cache->queues));
    return &cache->queues[index];
}

static struct sref_queue *
sref_cache_get_queue_by_epoch_id(struct sref_cache *cache,
                                 unsigned int epoch_id)
{
    size_t mask;

    mask = ARRAY_SIZE(cache->queues) - 1;
    return sref_cache_get_queue(cache, epoch_id & mask);
}

static void
sref_cache_schedule_review(struct sref_cache *cache,
                           struct sref_counter *counter)
{
    struct sref_queue *queue;

    assert(!sref_counter_is_queued(counter));
    assert(!sref_counter_is_dirty(counter));

    sref_counter_mark_queued(counter);
    sref_counter_mark_dying(counter);

    queue = sref_cache_get_queue_by_epoch_id(cache, cache->epoch_id);
    sref_queue_push(queue, counter);
}

static void
sref_counter_add(struct sref_counter *counter, unsigned long delta,
                 struct sref_cache *cache)
{
    assert(!cpu_intr_enabled());

    spinlock_lock(&counter->lock);

    counter->value += delta;

    if (counter->value == 0) {
        if (sref_counter_is_queued(counter)) {
            sref_counter_mark_dirty(counter);
        } else {
            sref_cache_schedule_review(cache, counter);
        }
    }

    spinlock_unlock(&counter->lock);
}

static void
sref_counter_noref(struct work *work)
{
    struct sref_counter *counter;

    counter = structof(work, struct sref_counter, work);
    counter->noref_fn(counter);
}

static void __init
sref_delta_init(struct sref_delta *delta)
{
    delta->counter = NULL;
    delta->value = 0;
}

static struct sref_counter *
sref_delta_counter(struct sref_delta *delta)
{
    return delta->counter;
}

static void
sref_delta_set_counter(struct sref_delta *delta, struct sref_counter *counter)
{
    assert(delta->value == 0);
    delta->counter = counter;
}

static void
sref_delta_clear(struct sref_delta *delta)
{
    assert(delta->value == 0);
    delta->counter = NULL;
}

static void
sref_delta_inc(struct sref_delta *delta)
{
    delta->value++;
}

static void
sref_delta_dec(struct sref_delta *delta)
{
    delta->value--;
}

static bool
sref_delta_is_valid(const struct sref_delta *delta)
{
    return delta->counter;
}

static void
sref_delta_flush(struct sref_delta *delta, struct sref_cache *cache)
{
    sref_counter_add(delta->counter, delta->value, cache);
    delta->value = 0;
}

static void
sref_delta_evict(struct sref_delta *delta, struct sref_cache *cache)
{
    sref_delta_flush(delta, cache);
    sref_delta_clear(delta);
}

static struct sref_cache *
sref_get_local_cache(void)
{
    return cpu_local_ptr(sref_cache);
}

static uintptr_t
sref_cache_compute_counter_index(const struct sref_cache *cache,
                                 const struct sref_counter *counter)
{
    return sref_counter_hash(counter) & (ARRAY_SIZE(cache->deltas) - 1);
}

static struct sref_delta *
sref_cache_get_delta(struct sref_cache *cache, size_t index)
{
    assert(index < ARRAY_SIZE(cache->deltas));
    return &cache->deltas[index];
}

static struct sref_cache *
sref_cache_acquire(unsigned long *flags)
{
    thread_preempt_disable_intr_save(flags);
    return sref_get_local_cache();
}

static void
sref_cache_release(unsigned long flags)
{
    thread_preempt_enable_intr_restore(flags);
}

static bool
sref_cache_is_dirty(const struct sref_cache *cache)
{
    return cache->dirty;
}

static void
sref_cache_set_dirty(struct sref_cache *cache)
{
    cache->dirty = true;
}

static void
sref_cache_clear_dirty(struct sref_cache *cache)
{
    cache->dirty = false;
}

static bool
sref_cache_is_flushed(const struct sref_cache *cache)
{
    return cache->flushed;
}

static void
sref_cache_set_flushed(struct sref_cache *cache)
{
    cache->flushed = true;
}

static void
sref_cache_clear_flushed(struct sref_cache *cache)
{
    cache->flushed = false;
}

static void
sref_cache_add_delta(struct sref_cache *cache, struct sref_delta *delta,
                     struct sref_counter *counter)
{
    assert(!sref_delta_is_valid(delta));
    assert(counter);

    sref_delta_set_counter(delta, counter);
    list_insert_tail(&cache->valid_deltas, &delta->node);
}

static void
sref_cache_remove_delta(struct sref_cache *cache, struct sref_delta *delta)
{
    assert(sref_delta_is_valid(delta));

    sref_delta_evict(delta, cache);
    list_remove(&delta->node);
}

static struct sref_delta *
sref_cache_take_delta(struct sref_cache *cache, struct sref_counter *counter)
{
    struct sref_delta *delta;
    size_t index;

    index = sref_cache_compute_counter_index(cache, counter);
    delta = sref_cache_get_delta(cache, index);

    if (!sref_delta_is_valid(delta)) {
        sref_cache_add_delta(cache, delta, counter);
    } else if (sref_delta_counter(delta) != counter) {
        sref_cache_remove_delta(cache, delta);
        sref_cache_add_delta(cache, delta, counter);
        syscnt_inc(&cache->sc_collisions);
    }

    return delta;
}

static bool
sref_cache_needs_management(struct sref_cache *cache)
{
    const struct sref_queue *queue;

    assert(!cpu_intr_enabled());
    assert(!thread_preempt_enabled());

    queue = sref_cache_get_queue_by_epoch_id(cache, cache->epoch_id - 2);
    return sref_cache_is_dirty(cache) || !sref_queue_empty(queue);
}

static void
sref_cache_end_epoch(struct sref_cache *cache)
{
    assert(!sref_cache_needs_management(cache));

    sref_data_ack_cpu(cache->data);
    cache->epoch_id++;
}

static void
sref_cache_flush(struct sref_cache *cache, struct sref_queue *queue)
{
    struct sref_queue *prev_queue;
    unsigned long flags;

    for (;;) {
        struct sref_delta *delta;

        thread_preempt_disable_intr_save(&flags);

        if (list_empty(&cache->valid_deltas)) {
            break;
        }

        delta = list_first_entry(&cache->valid_deltas, typeof(*delta), node);
        sref_cache_remove_delta(cache, delta);

        thread_preempt_enable_intr_restore(flags);
    }

    sref_cache_clear_dirty(cache);
    sref_cache_set_flushed(cache);

    prev_queue = sref_cache_get_queue_by_epoch_id(cache, cache->epoch_id - 2);
    sref_queue_move(queue, prev_queue);
    sref_queue_init(prev_queue);

    sref_cache_end_epoch(cache);

    thread_preempt_enable_intr_restore(flags);

    syscnt_inc(&cache->sc_flushes);
}

static void
sref_queue_review(struct sref_queue *queue, struct sref_cache *cache)
{
    int64_t nr_dirty_zeroes, nr_true_zeroes, nr_revives;
    struct sref_counter *counter;
    struct work_queue works;
    unsigned long flags;
    bool requeue;
    int error;

    nr_dirty_zeroes = 0;
    nr_true_zeroes = 0;
    nr_revives = 0;
    work_queue_init(&works);

    while (!sref_queue_empty(queue)) {
        counter = sref_queue_pop(queue);

        spinlock_lock_intr_save(&counter->lock, &flags);

#ifdef SREF_VERIFY
        assert(!sref_counter_is_unreferenced(counter));
#endif /* SREF_VERIFY */

        assert(sref_counter_is_queued(counter));
        sref_counter_clear_queued(counter);

        if (counter->value != 0) {
            sref_counter_clear_dirty(counter);
            sref_counter_clear_dying(counter);
            spinlock_unlock_intr_restore(&counter->lock, flags);
            continue;
        }

        if (sref_counter_is_dirty(counter)) {
            requeue = true;
            nr_dirty_zeroes++;
            sref_counter_clear_dirty(counter);
        } else {
            error = sref_counter_kill_weakref(counter);

            if (!error) {
                requeue = false;
            } else {
                requeue = true;
                nr_revives++;
            }
        }

        if (requeue) {
            sref_cache_schedule_review(cache, counter);
            spinlock_unlock_intr_restore(&counter->lock, flags);
        } else {

            /*
             * Keep in mind that the work structure shares memory with
             * the counter data.
             */

#ifdef SREF_VERIFY
            sref_counter_mark_unreferenced(counter);
#endif /* SREF_VERIFY */

            /*
             * Unlocking isn't needed here, since this counter is now
             * really at 0, but do it for consistency.
             */
            spinlock_unlock_intr_restore(&counter->lock, flags);

            nr_true_zeroes++;
            work_init(&counter->work, sref_counter_noref);
            work_queue_push(&works, &counter->work);
        }
    }

    if (work_queue_nr_works(&works) != 0) {
        work_queue_schedule(&works, WORK_HIGHPRIO);
    }

    sref_data_update_stats(cache->data, nr_dirty_zeroes,
                           nr_true_zeroes, nr_revives);
}

static void
sref_cache_manage(void *arg)
{
    struct sref_cache *cache;
    struct sref_queue queue;
    unsigned long flags;

    cache = arg;

    thread_preempt_disable_intr_save(&flags);

    for (;;) {

        while (sref_cache_is_flushed(cache)) {
            thread_sleep(NULL, cache, "sref");
        }

        thread_preempt_enable_intr_restore(flags);

        sref_cache_flush(cache, &queue);
        sref_queue_review(&queue, cache);

        thread_preempt_disable_intr_save(&flags);
    }

    /* Never reached */
}

static void
sref_cache_check(struct sref_cache *cache)
{
    bool same_epoch;

    same_epoch = sref_data_check_epoch_id(&sref_data, cache->epoch_id);

    if (!same_epoch) {
        return;
    }

    if (!sref_cache_needs_management(cache)) {
        sref_cache_end_epoch(cache);
        return;
    }

    sref_cache_clear_flushed(cache);
    thread_wakeup(cache->manager);
}

static void __init
sref_cache_init(struct sref_cache *cache, unsigned int cpu,
                struct sref_data *data)
{
    char name[SYSCNT_NAME_SIZE];

    cache->data = data;
    cache->dirty = false;
    cache->flushed = true;
    cache->epoch_id = sref_data_get_epoch_id(&sref_data) + 1;

    for (size_t i = 0; i < ARRAY_SIZE(cache->deltas); i++) {
        sref_delta_init(sref_cache_get_delta(cache, i));
    }

    list_init(&cache->valid_deltas);

    for (size_t i = 0; i < ARRAY_SIZE(cache->queues); i++) {
        sref_queue_init(sref_cache_get_queue(cache, i));
    }

    snprintf(name, sizeof(name), "sref_collisions/%u", cpu);
    syscnt_register(&cache->sc_collisions, name);
    snprintf(name, sizeof(name), "sref_flushes/%u", cpu);
    syscnt_register(&cache->sc_flushes, name);
    cache->manager = NULL;
}

static void __init
sref_cache_init_manager(struct sref_cache *cache, unsigned int cpu)
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
    snprintf(name, sizeof(name), THREAD_KERNEL_PREFIX "sref_cache_manage/%u",
             cpu);
    thread_attr_init(&attr, name);
    thread_attr_set_cpumap(&attr, cpumap);
    thread_attr_set_priority(&attr, THREAD_SCHED_FS_PRIO_MAX);
    error = thread_create(&manager, &attr, sref_cache_manage, cache);
    cpumap_destroy(cpumap);

    if (error) {
        panic("sref: unable to create manager thread");
    }

    cache->manager = manager;
}

static void __init
sref_data_init(struct sref_data *data)
{
    data->epoch_id = SREF_EPOCH_ID_INIT_VALUE;
    data->nr_pending_acks = 0;
    data->start_ts = clock_get_time();

    syscnt_register(&data->sc_epochs, "sref_epochs");
    syscnt_register(&data->sc_dirty_zeroes, "sref_dirty_zeroes");
    syscnt_register(&data->sc_true_zeroes, "sref_true_zeroes");
    syscnt_register(&data->sc_revives, "sref_revives");
    syscnt_register(&data->sc_last_epoch_ms, "sref_last_epoch_ms");
    syscnt_register(&data->sc_longest_epoch_ms, "sref_longest_epoch_ms");
}

static int __init
sref_bootstrap(void)
{
    sref_data_init(&sref_data);
    sref_cache_init(sref_get_local_cache(), 0, &sref_data);
    return 0;
}

INIT_OP_DEFINE(sref_bootstrap,
               INIT_OP_DEP(cpu_setup, true),
               INIT_OP_DEP(spinlock_setup, true),
               INIT_OP_DEP(syscnt_setup, true),
               INIT_OP_DEP(thread_bootstrap, true));

static int __init
sref_setup(void)
{
    for (unsigned int i = 1; i < cpu_count(); i++) {
        sref_cache_init(percpu_ptr(sref_cache, i), i, &sref_data);
    }

    for (unsigned int i = 0; i < cpu_count(); i++) {
        sref_cache_init_manager(percpu_ptr(sref_cache, i), i);
    }

    sref_data_start_epoch(&sref_data);

    return 0;
}

INIT_OP_DEFINE(sref_setup,
               INIT_OP_DEP(cpu_mp_probe, true),
               INIT_OP_DEP(cpumap_setup, true),
               INIT_OP_DEP(log_setup, true),
               INIT_OP_DEP(sref_bootstrap, true),
               INIT_OP_DEP(thread_setup, true));

void
sref_report_periodic_event(void)
{
    sref_cache_check(sref_get_local_cache());
}

void
sref_counter_init(struct sref_counter *counter,
                  unsigned long init_value,
                  struct sref_weakref *weakref,
                  sref_noref_fn_t noref_fn)
{
    assert(init_value != 0);

    counter->noref_fn = noref_fn;
    spinlock_init(&counter->lock);
    counter->flags = 0;
    counter->value = init_value;
    counter->weakref = weakref;

    if (weakref) {
        sref_weakref_init(weakref, counter);
    }
}

static void
sref_counter_inc_common(struct sref_counter *counter, struct sref_cache *cache)
{
    struct sref_delta *delta;

    sref_cache_set_dirty(cache);
    delta = sref_cache_take_delta(cache, counter);
    sref_delta_inc(delta);
}

void
sref_counter_inc(struct sref_counter *counter)
{
    struct sref_cache *cache;
    unsigned long flags;

    cache = sref_cache_acquire(&flags);
    sref_counter_inc_common(counter, cache);
    sref_cache_release(flags);
}

void
sref_counter_dec(struct sref_counter *counter)
{
    struct sref_cache *cache;
    struct sref_delta *delta;
    unsigned long flags;

    cache = sref_cache_acquire(&flags);
    sref_cache_set_dirty(cache);
    delta = sref_cache_take_delta(cache, counter);
    sref_delta_dec(delta);
    sref_cache_release(flags);
}

struct sref_counter *
sref_weakref_get(struct sref_weakref *weakref)
{
    struct sref_counter *counter;
    struct sref_cache *cache;
    unsigned long flags;

    cache = sref_cache_acquire(&flags);

    counter = sref_weakref_tryget(weakref);

    if (counter) {
        sref_counter_inc_common(counter, cache);
    }

    sref_cache_release(flags);

    return counter;
}
