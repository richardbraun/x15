/*
 * Copyright (c) 2017 Richard Braun.
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
 * This implementation is based on "Hashed and Hierarchical Timing Wheels:
 * Efficient Data Structures for Implementing a Timer Facility" by George
 * Varghese and Tony Lauck. Specifically, it implements scheme 6.1.2.
 *
 * TODO Analyse hash parameters.
 */

#include <assert.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <kern/atomic.h>
#include <kern/clock.h>
#include <kern/error.h>
#include <kern/init.h>
#include <kern/hlist.h>
#include <kern/macros.h>
#include <kern/panic.h>
#include <kern/percpu.h>
#include <kern/spinlock.h>
#include <kern/thread.h>
#include <kern/timer.h>
#include <kern/timer_i.h>
#include <kern/work.h>
#include <machine/boot.h>
#include <machine/cpu.h>

/*
 * Timer states.
 */
#define TIMER_TS_READY          1
#define TIMER_TS_SCHEDULED      2
#define TIMER_TS_RUNNING        3
#define TIMER_TS_DONE           4

/*
 * Timer flags.
 */
#define TIMER_TF_DETACHED       0x1
#define TIMER_TF_INTR           0x2
#define TIMER_TF_HIGH_PRIO      0x4
#define TIMER_TF_CANCELED       0x8

#define TIMER_INVALID_CPU ((unsigned int)-1)

#define TIMER_HTABLE_SIZE 2048

#if !ISP2(TIMER_HTABLE_SIZE)
#error "hash table size must be a power of two"
#endif /* !ISP2(TIMER_HTABLE_SIZE) */

#define TIMER_HTABLE_MASK (TIMER_HTABLE_SIZE - 1)

struct timer_bucket {
    struct hlist timers;
};

/*
 * The hash table bucket matching the last time member has already been
 * processed, and the next periodic event resumes from the next bucket.
 *
 * Locking order: interrupts -> timer_cpu_data.
 */
struct timer_cpu_data {
    unsigned int cpu;
    struct spinlock lock;
    uint64_t last_time;
    struct timer_bucket htable[TIMER_HTABLE_SIZE];
};

static struct timer_cpu_data timer_cpu_data __percpu;

static struct timer_cpu_data *
timer_cpu_data_acquire(unsigned long *flags)
{
    struct timer_cpu_data *cpu_data;

    thread_preempt_disable();
    cpu_data = cpu_local_ptr(timer_cpu_data);
    spinlock_lock_intr_save(&cpu_data->lock, flags);
    thread_preempt_enable_no_resched();

    return cpu_data;
}

static struct timer_cpu_data *
timer_lock_cpu_data(struct timer *timer, unsigned long *flags)
{
    struct timer_cpu_data *cpu_data;
    unsigned int cpu;

    for (;;) {
        cpu = atomic_load(&timer->cpu, ATOMIC_RELAXED);

        if (cpu == TIMER_INVALID_CPU) {
            return NULL;
        }

        cpu_data = percpu_ptr(timer_cpu_data, cpu);

        spinlock_lock_intr_save(&cpu_data->lock, flags);

        if (cpu == atomic_load(&timer->cpu, ATOMIC_RELAXED)) {
            return cpu_data;
        }

        spinlock_unlock_intr_restore(&cpu_data->lock, *flags);
    }
}

static void
timer_unlock_cpu_data(struct timer_cpu_data *cpu_data, unsigned long flags)
{
    spinlock_unlock_intr_restore(&cpu_data->lock, flags);
}

/*
 * Timer state functions.
 */

__unused static bool
timer_ready(const struct timer *timer)
{
    return timer->state == TIMER_TS_READY;
}

static void
timer_set_ready(struct timer *timer)
{
    timer->state = TIMER_TS_READY;
}

static bool
timer_scheduled(const struct timer *timer)
{
    return timer->state == TIMER_TS_SCHEDULED;
}

static void
timer_set_scheduled(struct timer *timer, unsigned int cpu)
{
    atomic_store(&timer->cpu, cpu, ATOMIC_RELAXED);
    timer->state = TIMER_TS_SCHEDULED;
}

static bool
timer_running(const struct timer *timer)
{
    return timer->state == TIMER_TS_RUNNING;
}

static void
timer_set_running(struct timer *timer)
{
    timer->state = TIMER_TS_RUNNING;
}

static bool
timer_done(const struct timer *timer)
{
    return timer->state == TIMER_TS_DONE;
}

static void
timer_set_done(struct timer *timer)
{
    timer->state = TIMER_TS_DONE;
}

/*
 * Timer flags functions.
 */

static bool
timer_detached(const struct timer *timer)
{
    return timer->flags & TIMER_TF_DETACHED;
}

static void
timer_set_detached(struct timer *timer)
{
    timer->flags |= TIMER_TF_DETACHED;
}

static bool
timer_is_intr(const struct timer *timer)
{
    return timer->flags & TIMER_TF_INTR;
}

static void
timer_set_intr(struct timer *timer)
{
    timer->flags |= TIMER_TF_INTR;
}

static bool
timer_is_high_prio(const struct timer *timer)
{
    return timer->flags & TIMER_TF_HIGH_PRIO;
}

static void
timer_set_high_prio(struct timer *timer)
{
    timer->flags |= TIMER_TF_HIGH_PRIO;
}

static bool
timer_canceled(const struct timer *timer)
{
    return timer->flags & TIMER_TF_CANCELED;
}

static void
timer_set_canceled(struct timer *timer)
{
    timer->flags |= TIMER_TF_CANCELED;
}

static void
timer_set_time(struct timer *timer, uint64_t ticks)
{
    timer->ticks = ticks;
}

static bool
timer_occurred(const struct timer *timer, uint64_t ref)
{
    return clock_time_occurred(timer_get_time(timer), ref);
}

static uintptr_t
timer_hash(uint64_t ticks)
{
    return ticks;
}

static void
timer_run(struct timer *timer)
{
    struct timer_cpu_data *cpu_data;
    unsigned long cpu_flags;

    assert(timer_running(timer));

    timer->fn(timer);

    if (timer_detached(timer)) {
        return;
    }

    cpu_data = timer_lock_cpu_data(timer, &cpu_flags);

    /*
     * The timer handler may have :
     *  - rescheduled itself
     *  - been canceled
     *  - none of the above
     *
     * If the handler didn't call a timer function, or if the timer was
     * canceled, set the state to done and wake up the joiner, if any.
     *
     * If the handler rescheduled the timer, nothing must be done. This
     * is also true if the timer was canceled after being rescheduled by
     * the handler (in this case, cancellation won't wait for a signal).
     * These cases can be identified by checking if the timer state is
     * different from running.
     */

    if (timer_running(timer)) {
        timer_set_done(timer);
        thread_wakeup(timer->joiner);
    }

    timer_unlock_cpu_data(cpu_data, cpu_flags);
}

static void
timer_run_work(struct work *work)
{
    struct timer *timer;

    timer = structof(work, struct timer, work);
    timer_run(timer);
}

static void
timer_process(struct timer *timer)
{
    int work_flags;

    if (timer_is_intr(timer)) {
        timer_run(timer);
        return;
    }

    if (timer_is_high_prio(timer)) {
        work_flags = TIMER_TF_HIGH_PRIO;
    } else {
        work_flags = 0;
    }

    work_init(&timer->work, timer_run_work);
    work_schedule(&timer->work, work_flags);
}

static void
timer_bucket_init(struct timer_bucket *bucket)
{
    hlist_init(&bucket->timers);
}

static void
timer_bucket_add(struct timer_bucket *bucket, struct timer *timer)
{
    hlist_insert_head(&bucket->timers, &timer->node);
}

static void
timer_bucket_remove(struct timer_bucket *bucket, struct timer *timer)
{
    (void)bucket;
    hlist_remove(&timer->node);
}

static void
timer_cpu_data_init(struct timer_cpu_data *cpu_data, unsigned int cpu)
{
    cpu_data->cpu = cpu;
    spinlock_init(&cpu_data->lock);

    /* See periodic event handling */
    cpu_data->last_time = clock_get_time() - 1;

    for (size_t i = 0; i < ARRAY_SIZE(cpu_data->htable); i++) {
        timer_bucket_init(&cpu_data->htable[i]);
    }
}

static struct timer_bucket *
timer_cpu_data_get_bucket(struct timer_cpu_data *cpu_data, uint64_t ticks)
{
    uintptr_t index;

    index = timer_hash(ticks) & TIMER_HTABLE_MASK;
    assert(index < ARRAY_SIZE(cpu_data->htable));
    return &cpu_data->htable[index];
}

static void
timer_cpu_data_add(struct timer_cpu_data *cpu_data, struct timer *timer)
{
    struct timer_bucket *bucket;

    assert(timer_ready(timer));

    bucket = timer_cpu_data_get_bucket(cpu_data, timer->ticks);
    timer_bucket_add(bucket, timer);
}

static void
timer_cpu_data_remove(struct timer_cpu_data *cpu_data, struct timer *timer)
{
    struct timer_bucket *bucket;

    assert(timer_scheduled(timer));

    bucket = timer_cpu_data_get_bucket(cpu_data, timer->ticks);
    timer_bucket_remove(bucket, timer);
}

static void
timer_bucket_filter(struct timer_bucket *bucket, uint64_t now,
                    struct hlist *timers)
{
    struct timer *timer, *tmp;

    hlist_for_each_entry_safe(&bucket->timers, timer, tmp, node) {
        assert(timer_scheduled(timer));

        if (!timer_occurred(timer, now)) {
            continue;
        }

        hlist_remove(&timer->node);
        timer_set_running(timer);
        hlist_insert_head(timers, &timer->node);
    }
}

static int __init
timer_setup(void)
{
    for (unsigned int cpu = 0; cpu < cpu_count(); cpu++) {
        timer_cpu_data_init(percpu_ptr(timer_cpu_data, cpu), cpu);
    }

    return 0;
}

INIT_OP_DEFINE(timer_setup,
               INIT_OP_DEP(boot_setup_intr, true),
               INIT_OP_DEP(cpu_mp_probe, true));

void timer_init(struct timer *timer, timer_fn_t fn, int flags)
{
    timer->fn = fn;
    timer->cpu = TIMER_INVALID_CPU;
    timer->state = TIMER_TS_READY;
    timer->flags = 0;
    timer->joiner = NULL;

    if (flags & TIMER_DETACHED) {
        timer_set_detached(timer);
    }

    if (flags & TIMER_INTR) {
        timer_set_intr(timer);
    } else if (flags & TIMER_HIGH_PRIO) {
        timer_set_high_prio(timer);
    }
}

void
timer_schedule(struct timer *timer, uint64_t ticks)
{
    struct timer_cpu_data *cpu_data;
    unsigned long cpu_flags;

    cpu_data = timer_lock_cpu_data(timer, &cpu_flags);

    if (cpu_data == NULL) {
        cpu_data = timer_cpu_data_acquire(&cpu_flags);
    } else {
        if (timer_canceled(timer)) {
            goto out;
        }

        /*
         * If called from the handler, the timer is running. If rescheduled
         * after completion, it's done.
         */
        if (timer_running(timer) || timer_done(timer)) {
            timer_set_ready(timer);
        }
    }

    timer_set_time(timer, ticks);

    if (timer_occurred(timer, cpu_data->last_time)) {
        ticks = cpu_data->last_time + 1;
    }

    timer_cpu_data_add(cpu_data, timer);
    timer_set_scheduled(timer, cpu_data->cpu);

out:
    timer_unlock_cpu_data(cpu_data, cpu_flags);
}

void
timer_cancel(struct timer *timer)
{
    struct timer_cpu_data *cpu_data;
    unsigned long cpu_flags;

    assert(!timer_detached(timer));

    cpu_data = timer_lock_cpu_data(timer, &cpu_flags);

    assert(timer->joiner == NULL);

    timer_set_canceled(timer);

    if (timer_scheduled(timer)) {
        timer_cpu_data_remove(cpu_data, timer);
    } else {
        timer->joiner = thread_self();

        while (!timer_done(timer)) {
            if (timer_is_intr(timer)) {
                timer_unlock_cpu_data(cpu_data, cpu_flags);
                cpu_pause();
                cpu_data = timer_lock_cpu_data(timer, &cpu_flags);
            } else {
                thread_sleep(&cpu_data->lock, timer, "tmr_cncl");
            }
        }

        assert(timer_done(timer));

        timer->joiner = NULL;
    }

    timer_set_ready(timer);

    timer_unlock_cpu_data(cpu_data, cpu_flags);
}

void
timer_report_periodic_event(void)
{
    struct timer_cpu_data *cpu_data;
    struct timer_bucket *bucket;
    struct timer *timer;
    struct hlist timers;
    uint64_t ticks, now;

    assert(thread_check_intr_context());

    now = clock_get_time();
    hlist_init(&timers);
    cpu_data = cpu_local_ptr(timer_cpu_data);

    spinlock_lock(&cpu_data->lock);

    for (ticks = cpu_data->last_time + 1;
         clock_time_occurred(ticks, now);
         ticks++) {
        bucket = timer_cpu_data_get_bucket(cpu_data, ticks);
        timer_bucket_filter(bucket, now, &timers);
    }

    cpu_data->last_time = now;

    spinlock_unlock(&cpu_data->lock);

    while (!hlist_empty(&timers)) {
        timer = hlist_first_entry(&timers, struct timer, node);
        hlist_remove(&timer->node);
        timer_process(timer);
    }
}
