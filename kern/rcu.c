/*
 * Copyright (c) 2018 Richard Braun.
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
 * This implementation is based on the paper "Extending RCU for Realtime
 * and Embedded Workloads" by Paul E. McKenney, Ingo Molnar, Dipankar Sarma,
 * and Suparna Bhattacharya. Beside the mechanisms not implemented yet,
 * such as priority boosting, the differences are described below.
 *
 * First, this implementation uses scalable reference counters provided
 * by the sref module instead of per-CPU counters as described in the paper.
 * The main benefit of this approach is the centralization of most scalability
 * improvements in the sref module, which should propagate to all sref users,
 * including RCU.
 *
 * In addition, this implementation introduces the concept of windows, where
 * a window is a range in time to which readers may be linked. Here, a
 * grace period is defined as the time range at the end of a window where
 * various synchronization steps are performed to enforce the RCU guarantees.
 * The minimum duration of a window acts as a knob allowing users to tune
 * the behavior of the RCU system.
 *
 * Finally, the state machine described in the paper is updated to accommodate
 * for windows, since grace periods don't run back-to-back to each other.
 * Windows are regularly checked and flipped if the previous one isn't
 * active any more. From that moment, processors may notice the global flip
 * and perform a local flip of their work window ID. Once all processors
 * have acknowleged the flip, it is certain that no new work may be queued
 * on the previous window. At this point, the same occurs for the
 * processor-local reader window ID, and once all processors have
 * acknowleged that flip, there can be no new reader linked to the previous
 * window. The RCU system then releases its own reference to the previous
 * window and waits for the window reference counter to drop to 0, indicating
 * that all readers linked to the previous window have left their read-side
 * critical section. When this global event occurs, processors are requested
 * to flush the works queued for the previous window, and once they all have
 * acknowleged their flush, the window ends and becomes inactive, allowing
 * a new grace period to occur later on.
 *
 * Here is an informal diagram describing this process :
 *
 * t ---->
 *
 *    reader window flip ---+     +--- no more readers
 * work window flip ------+ |     | +- works flushed
 * (grace period start)   | |     | |  (grace period / window end)
 *                        v v     v v
 *         +--------------+-+-----+-+
 *         |              . .     . |
 *         |  window 0    . . gp  . |
 *         |      removal . .     . | reclamation
 *         +--------------+-+-----+-+-----+----+
 *                        |               .    |
 *                        |  window 1     . gp |
 *                        |       removal .    | reclamation
 *                        +---------------+----+--------
 *                                        |
 *                                        |  window 2   ...
 *                                        |
 *                                        +-------------
 *
 * On each processor, work window flips are separate from reader window
 * flips in order to correctly handle situations such as this one, where
 * "wf" denotes a window flip for both works and readers :
 *
 * t ---->
 *
 * CPU0   wf load                           flush
 * CPU1            wf                       flush
 * global          no-new-reader ... no-ref       loaded value now invalid
 *
 * After its window flip, CPU0 may load data from the previous window with
 * a reader linked to the current window, because it doesn't know that there
 * may still be new works queued on the previous window.
 *
 * TODO Improve atomic acknowledgment scalability.
 * TODO Handle large amounts of deferred works.
 * TODO Priority boosting of slow readers.
 * TODO CPU registration for dyntick-friendly behavior.
 */

#include <assert.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include <kern/atomic.h>
#include <kern/clock.h>
#include <kern/init.h>
#include <kern/macros.h>
#include <kern/rcu.h>
#include <kern/panic.h>
#include <kern/percpu.h>
#include <kern/spinlock.h>
#include <kern/sref.h>
#include <kern/syscnt.h>
#include <kern/thread.h>
#include <kern/timer.h>
#include <kern/work.h>
#include <machine/cpu.h>

/*
 * Negative close to 0 so that an overflow occurs early.
 */
#define RCU_WINDOW_ID_INIT_VALUE ((unsigned int)-500)

/*
 * Interval (in milliseconds) between window checking.
 *
 * When windows are checked, a flip occurs if the previous window isn't
 * active any more.
 */
#define RCU_WINDOW_CHECK_INTERVAL CONFIG_RCU_WINDOW_CHECK_INTERVAL

/*
 * Grace period states.
 *
 * These states are only used to trigger per-CPU processing that is
 * globally acknowleged by decrementing a global atomic counter. They
 * do not completely represent the actual state of a grace period.
 */
enum rcu_gp_state {
    RCU_GP_STATE_WORK_WINDOW_FLIP,
    RCU_GP_STATE_READER_WINDOW_FLIP,
    RCU_GP_STATE_WORK_FLUSH,
};

/*
 * Per-CPU view of a window.
 *
 * Deferred works are scheduled when the window ends.
 */
struct rcu_cpu_window {
    struct work_queue works;
};

/*
 * Per-CPU RCU data.
 *
 * Each processor maintains two local window IDs. One is used as the current
 * window ID when deferring work, the other when detecting a reader. A local
 * flip occurs when a processor notices that the global grace period state
 * no longer matches the local grace period state. These checks only occur
 * on periodic events.
 *
 * Interrupts and preemption must be disabled when accessing local CPU data.
 */
struct rcu_cpu_data {
    enum rcu_gp_state gp_state;
    unsigned int work_wid;
    unsigned int reader_wid;
    struct rcu_cpu_window windows[2];
    struct syscnt sc_nr_detected_readers;
};

/*
 * Global window.
 *
 * A window is a time range that tracks read-side references. Conceptually,
 * each reader adds a reference to the current window. In practice, references
 * are only added when readers are detected, which occurs on a context switch
 * (to track preempted threads) or a reader window flip (to prevent currently
 * running readers to be linked to the next window).
 *
 * When a window is started, its scalable reference counter is initialized
 * with a reference owned by the RCU system. That reference guarantees that
 * the window remains active as long as new readers may add references,
 * since it prevents the counter from dropping to 0. After a reader window
 * flip, there may not be new references to the window, and the initial
 * reference is dropped, allowing the counter to reach 0 once all detected
 * readers leave their critical section and unreference the window they're
 * linked to.
 */
struct rcu_window {
    struct sref_counter nr_refs;
    uint64_t start_ts;
    bool active;
};

/*
 * Global data.
 *
 * Processors regularly check the grace period state against their own,
 * locally cached grace period state, and take action whenever they differ.
 * False sharing is avoided by making the global grace period state fill an
 * entire cache line on SMP.
 *
 * After processors notice a grace period state change, they acknowledge
 * noticing this change by decrementing the atomic acknowledgment counter,
 * which also fills a complete cache line on SMP in order to restrict cache
 * line bouncing. Atomic operations on this counter are done with
 * acquire-release ordering to enforce the memory ordering guarantees
 * required by the implementation, as well as those provided by the public
 * interface.
 *
 * In addition to the global window ID and the windows themselves, the data
 * include a timer, used to trigger the end of windows, i.e. grace periods.
 * Since the timer function, atomic acknowledgments, and window no-reference
 * function chain each other, there is currently no need for a global lock.
 */
struct rcu_data {
    struct {
        alignas(CPU_L1_SIZE) enum rcu_gp_state gp_state;
    };
    struct {
        alignas(CPU_L1_SIZE) unsigned int nr_acks;
    };

    unsigned int wid;
    struct rcu_window windows[2];
    struct timer timer;
    struct syscnt sc_nr_windows;
    struct syscnt sc_last_window_ms;
    struct syscnt sc_longest_window_ms;
};

/*
 * Structure used to implement rcu_wait().
 */
struct rcu_waiter {
    struct work work;
    struct spinlock lock;
    struct thread *thread;
    bool done;
};

static struct rcu_data rcu_data;
static struct rcu_cpu_data rcu_cpu_data __percpu;

static struct rcu_cpu_data *
rcu_get_cpu_data(void)
{
    assert(!cpu_intr_enabled());
    assert(!thread_preempt_enabled());

    return cpu_local_ptr(rcu_cpu_data);
}

static enum rcu_gp_state
rcu_data_get_gp_state(const struct rcu_data *data)
{
    return data->gp_state;
}

static unsigned int
rcu_data_get_wid(const struct rcu_data *data)
{
    return data->wid;
}

static struct rcu_window *
rcu_data_get_window_from_index(struct rcu_data *data, size_t index)
{
    assert(index < ARRAY_SIZE(data->windows));
    return &data->windows[index];
}

static struct rcu_window *
rcu_data_get_window(struct rcu_data *data, unsigned int wid)
{
    return rcu_data_get_window_from_index(data, wid & 1);
}

static void
rcu_data_update_gp_state(struct rcu_data *data, enum rcu_gp_state gp_state)
{
    assert(data->nr_acks  == 0);

    switch (gp_state) {
    case RCU_GP_STATE_WORK_WINDOW_FLIP:
        assert(data->gp_state == RCU_GP_STATE_WORK_FLUSH);
        break;
    case RCU_GP_STATE_READER_WINDOW_FLIP:
        assert(data->gp_state == RCU_GP_STATE_WORK_WINDOW_FLIP);
        break;
    case RCU_GP_STATE_WORK_FLUSH:
        assert(data->gp_state == RCU_GP_STATE_READER_WINDOW_FLIP);
        break;
    default:
        panic("rcu: invalid grace period state");
    }

    data->nr_acks = cpu_count();
    atomic_store(&data->gp_state, gp_state, ATOMIC_RELEASE);
}

static bool
rcu_data_check_gp_state(const struct rcu_data *data,
                        enum rcu_gp_state local_gp_state,
                        enum rcu_gp_state *global_gp_state)
{
    *global_gp_state = atomic_load(&data->gp_state, ATOMIC_RELAXED);

    if (unlikely(local_gp_state != *global_gp_state)) {
        atomic_fence(ATOMIC_ACQUIRE);
        return true;
    }

    return false;
}

static void
rcu_window_end(struct rcu_window *window)
{
    assert(window->active);
    window->active = false;
}

static void
rcu_window_ref(struct rcu_window *window)
{
    sref_counter_inc(&window->nr_refs);
}

static void
rcu_window_unref(struct rcu_window *window)
{
    sref_counter_dec(&window->nr_refs);
}

static uint64_t
rcu_window_get_start_ts(const struct rcu_window *window)
{
    return window->start_ts;
}

static void
rcu_window_flush(struct sref_counter *counter)
{
    (void)counter;

    rcu_data_update_gp_state(&rcu_data, RCU_GP_STATE_WORK_FLUSH);
}

static void __init
rcu_window_init(struct rcu_window *window)
{
    window->active = false;
}

static void
rcu_window_start(struct rcu_window *window)
{
    assert(!window->active);

    sref_counter_init(&window->nr_refs, 1, NULL, rcu_window_flush);
    window->start_ts = clock_get_time();
    window->active = true;
}

static bool
rcu_window_active(const struct rcu_window *window)
{
    return window->active;
}

static void
rcu_data_end_prev_window(struct rcu_data *data, uint64_t now)
{
    struct rcu_window *window;
    uint64_t duration;

    window = rcu_data_get_window(data, data->wid - 1);
    duration = clock_ticks_to_ms(now - rcu_window_get_start_ts(window));
    syscnt_set(&data->sc_last_window_ms, duration);

    if (duration > syscnt_read(&data->sc_longest_window_ms)) {
        syscnt_set(&data->sc_longest_window_ms, duration);
    }

    rcu_window_end(window);
}

static void
rcu_data_schedule_timer(struct rcu_data *data, uint64_t now)
{
    uint64_t ticks;

    ticks = clock_ticks_from_ms(RCU_WINDOW_CHECK_INTERVAL);
    timer_schedule(&data->timer, now + ticks);
}

static void
rcu_data_ack_cpu(struct rcu_data *data)
{
    struct rcu_window *window;
    unsigned int prev_nr_acks;
    uint64_t now;

    prev_nr_acks = atomic_fetch_sub(&data->nr_acks, 1, ATOMIC_ACQ_REL);

    if (prev_nr_acks != 1) {
        assert(prev_nr_acks != 0);
        return;
    }

    switch (data->gp_state) {
    case RCU_GP_STATE_WORK_WINDOW_FLIP:
        rcu_data_update_gp_state(data, RCU_GP_STATE_READER_WINDOW_FLIP);
        break;
    case RCU_GP_STATE_READER_WINDOW_FLIP:
        window = rcu_data_get_window(data, data->wid - 1);
        rcu_window_unref(window);
        break;
    case RCU_GP_STATE_WORK_FLUSH:
        now = clock_get_time();
        rcu_data_end_prev_window(data, now);
        rcu_data_schedule_timer(data, now);
        break;
    default:
        panic("rcu: invalid grace period state");
    }
}

static bool
rcu_data_flip_windows(struct rcu_data *data)
{
    struct rcu_window *window;

    window = rcu_data_get_window(data, data->wid - 1);

    if (rcu_window_active(window)) {
        return false;
    }

    rcu_window_start(window);
    syscnt_inc(&data->sc_nr_windows);
    data->wid++;
    rcu_data_update_gp_state(data, RCU_GP_STATE_WORK_WINDOW_FLIP);
    return true;
}

static void
rcu_data_check_windows(struct timer *timer)
{
    struct rcu_data *data;
    bool flipped;

    data = &rcu_data;
    flipped = rcu_data_flip_windows(data);

    if (!flipped) {
        rcu_data_schedule_timer(data, timer_get_time(timer));
    }
}

static void __init
rcu_data_init(struct rcu_data *data)
{
    data->gp_state = RCU_GP_STATE_WORK_FLUSH;
    data->nr_acks = 0;
    data->wid = RCU_WINDOW_ID_INIT_VALUE;

    for (size_t i = 0; i < ARRAY_SIZE(data->windows); i++) {
        rcu_window_init(rcu_data_get_window_from_index(data, i));
    }

    rcu_window_start(rcu_data_get_window(data, data->wid));

    timer_init(&data->timer, rcu_data_check_windows, 0);
    rcu_data_schedule_timer(data, clock_get_time());

    syscnt_register(&data->sc_nr_windows, "rcu_nr_windows");
    syscnt_register(&data->sc_last_window_ms, "rcu_last_window_ms");
    syscnt_register(&data->sc_longest_window_ms, "rcu_longest_window_ms");
}

static void __init
rcu_cpu_window_init(struct rcu_cpu_window *cpu_window)
{
    work_queue_init(&cpu_window->works);
}

static void
rcu_cpu_window_queue(struct rcu_cpu_window *cpu_window, struct work *work)
{
    work_queue_push(&cpu_window->works, work);
}

static void
rcu_cpu_window_flush(struct rcu_cpu_window *cpu_window)
{
    work_queue_schedule(&cpu_window->works, 0);
    work_queue_init(&cpu_window->works);
}

static unsigned int
rcu_cpu_data_get_reader_wid(const struct rcu_cpu_data *cpu_data)
{
    return cpu_data->reader_wid;
}

static struct rcu_cpu_window *
rcu_cpu_data_get_window_from_index(struct rcu_cpu_data *cpu_data, size_t index)
{
    assert(index < ARRAY_SIZE(cpu_data->windows));
    return &cpu_data->windows[index];
}

static struct rcu_cpu_window *
rcu_cpu_data_get_window(struct rcu_cpu_data *cpu_data, unsigned int wid)
{
    return rcu_cpu_data_get_window_from_index(cpu_data, wid & 1);
}

static void __init
rcu_cpu_data_init(struct rcu_cpu_data *cpu_data, unsigned int cpu)
{
    struct rcu_data *data;
    char name[SYSCNT_NAME_SIZE];

    data = &rcu_data;

    cpu_data->gp_state = rcu_data_get_gp_state(data);
    cpu_data->work_wid = rcu_data_get_wid(data);
    cpu_data->reader_wid = cpu_data->work_wid;

    for (size_t i = 0; i < ARRAY_SIZE(cpu_data->windows); i++) {
        rcu_cpu_window_init(rcu_cpu_data_get_window_from_index(cpu_data, i));
    }

    snprintf(name, sizeof(name), "rcu_nr_detected_readers/%u", cpu);
    syscnt_register(&cpu_data->sc_nr_detected_readers, name);
}

static void
rcu_cpu_data_queue(struct rcu_cpu_data *cpu_data, struct work *work)
{
    struct rcu_cpu_window *cpu_window;

    cpu_window = rcu_cpu_data_get_window(cpu_data, cpu_data->work_wid);
    rcu_cpu_window_queue(cpu_window, work);
}

static void
rcu_cpu_data_flush(struct rcu_cpu_data *cpu_data)
{
    struct rcu_cpu_window *cpu_window;

    assert(cpu_data->work_wid == cpu_data->reader_wid);

    cpu_window = rcu_cpu_data_get_window(cpu_data, cpu_data->work_wid - 1);
    rcu_cpu_window_flush(cpu_window);
}

void
rcu_reader_init(struct rcu_reader *reader)
{
    reader->level = 0;
    reader->linked = false;
}

static void
rcu_reader_link(struct rcu_reader *reader, struct rcu_cpu_data *cpu_data)
{
    assert(!cpu_intr_enabled());
    assert(reader == thread_rcu_reader(thread_self()));
    assert(!rcu_reader_linked(reader));

    reader->wid = rcu_cpu_data_get_reader_wid(cpu_data);
    reader->linked = true;
}

static void
rcu_reader_unlink(struct rcu_reader *reader)
{
    assert(reader->level == 0);
    reader->linked = false;
}

static void
rcu_reader_enter(struct rcu_reader *reader, struct rcu_cpu_data *cpu_data)
{
    struct rcu_window *window;
    struct rcu_data *data;
    unsigned int wid;

    if (rcu_reader_linked(reader)) {
        return;
    }

    data = &rcu_data;
    wid = rcu_cpu_data_get_reader_wid(cpu_data);
    window = rcu_data_get_window(data, wid);

    rcu_reader_link(reader, cpu_data);
    rcu_window_ref(window);

    syscnt_inc(&cpu_data->sc_nr_detected_readers);
}

void
rcu_reader_leave(struct rcu_reader *reader)
{
    struct rcu_window *window;
    struct rcu_data *data;

    data = &rcu_data;

    window = rcu_data_get_window(data, reader->wid);
    rcu_window_unref(window);
    rcu_reader_unlink(reader);
}

static void
rcu_reader_account(struct rcu_reader *reader, struct rcu_cpu_data *cpu_data)
{
    if (rcu_reader_in_cs(reader)) {
        rcu_reader_enter(reader, cpu_data);
    }
}

static void
rcu_cpu_data_flip_work_wid(struct rcu_cpu_data *cpu_data)
{
    assert(!cpu_intr_enabled());
    assert(!thread_preempt_enabled());

    cpu_data->work_wid++;
}

static void
rcu_cpu_data_flip_reader_wid(struct rcu_cpu_data *cpu_data)
{
    assert(!cpu_intr_enabled());
    assert(!thread_preempt_enabled());

    rcu_reader_account(thread_rcu_reader(thread_self()), cpu_data);
    cpu_data->reader_wid++;
}

static void
rcu_cpu_data_check_gp_state(struct rcu_cpu_data *cpu_data)
{
    enum rcu_gp_state local_gp_state, global_gp_state;
    struct rcu_data *data;
    bool diff;

    data = &rcu_data;

    /*
     * A loop is used to optimize the case where a processor is the last to
     * acknowledge a grace period state change, in which case the latter
     * also immediately changes and can be acknowleged right away. As a
     * result, this loop may never run more than twice.
     */
    for (unsigned int i = 0; /* no condition */; i++) {
        local_gp_state = cpu_data->gp_state;
        diff = rcu_data_check_gp_state(data, local_gp_state, &global_gp_state);

        if (!diff) {
            break;
        }

        assert(i < 2);

        switch (global_gp_state) {
        case RCU_GP_STATE_WORK_WINDOW_FLIP:
            rcu_cpu_data_flip_work_wid(cpu_data);
            rcu_data_ack_cpu(data);
            break;
        case RCU_GP_STATE_READER_WINDOW_FLIP:
            rcu_cpu_data_flip_reader_wid(cpu_data);
            rcu_data_ack_cpu(data);
            break;
        case RCU_GP_STATE_WORK_FLUSH:
            rcu_cpu_data_flush(cpu_data);
            rcu_data_ack_cpu(data);
            break;
        default:
            panic("rcu: invalid grace period state");
        }

        cpu_data->gp_state = global_gp_state;
    }
}

void
rcu_report_context_switch(struct rcu_reader *reader)
{
    assert(!cpu_intr_enabled());
    assert(!thread_preempt_enabled());

    /*
     * Most readers don't need to be accounted for because their execution
     * doesn't overlap with a grace period. If a reader is preempted however,
     * it must be accounted in case a grace period starts while the reader
     * is preempted. Accounting also occurs when a grace period starts, and
     * more exactly, when the reader window ID of a processor is flipped.
     */
    rcu_reader_account(reader, rcu_get_cpu_data());
}

void
rcu_report_periodic_event(void)
{
    assert(!cpu_intr_enabled());
    assert(!thread_preempt_enabled());

    rcu_cpu_data_check_gp_state(rcu_get_cpu_data());
}

void
rcu_defer(struct work *work)
{
    struct rcu_cpu_data *cpu_data;
    unsigned long flags;

    assert(!rcu_reader_in_cs(thread_rcu_reader(thread_self())));

    thread_preempt_disable_intr_save(&flags);
    cpu_data = rcu_get_cpu_data();
    rcu_cpu_data_queue(cpu_data, work);
    thread_preempt_enable_intr_restore(flags);
}

static void
rcu_waiter_wakeup(struct work *work)
{
    struct rcu_waiter *waiter;

    waiter = structof(work, struct rcu_waiter, work);

    spinlock_lock(&waiter->lock);
    waiter->done = true;
    thread_wakeup(waiter->thread);
    spinlock_unlock(&waiter->lock);
}

static void
rcu_waiter_init(struct rcu_waiter *waiter, struct thread *thread)
{
    work_init(&waiter->work, rcu_waiter_wakeup);
    spinlock_init(&waiter->lock);
    waiter->thread = thread;
    waiter->done = false;
}

static void
rcu_waiter_wait(struct rcu_waiter *waiter)
{
    rcu_defer(&waiter->work);

    spinlock_lock(&waiter->lock);

    while (!waiter->done) {
        thread_sleep(&waiter->lock, waiter, "rcu_wait");
    }

    spinlock_unlock(&waiter->lock);
}

void
rcu_wait(void)
{
    struct rcu_waiter waiter;

    rcu_waiter_init(&waiter, thread_self()),
    rcu_waiter_wait(&waiter);
}

static int __init
rcu_bootstrap(void)
{
    rcu_data_init(&rcu_data);
    rcu_cpu_data_init(cpu_local_ptr(rcu_cpu_data), 0);
    return 0;
}

INIT_OP_DEFINE(rcu_bootstrap,
               INIT_OP_DEP(spinlock_setup, true),
               INIT_OP_DEP(sref_bootstrap, true),
               INIT_OP_DEP(syscnt_setup, true),
               INIT_OP_DEP(thread_bootstrap, true),
               INIT_OP_DEP(timer_bootstrap, true));

static int __init
rcu_setup(void)
{
    for (unsigned int i = 1; i < cpu_count(); i++) {
        rcu_cpu_data_init(percpu_ptr(rcu_cpu_data, i), i);
    }

    return 0;
}

INIT_OP_DEFINE(rcu_setup,
               INIT_OP_DEP(cpu_mp_probe, true),
               INIT_OP_DEP(rcu_bootstrap, true));
