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
 *
 *
 * The method used by this module is described in the expired US patent
 * 4809168, "Passive Serialization in a Multitasking Environment". It is
 * similar to "Classic RCU (Read-Copy Update)" as found in Linux 2.6, with
 * the notable difference that RCU actively starts grace periods, where
 * passive serialization waits for two sequential "multiprocess checkpoints"
 * (renamed global checkpoints in this implementation) to occur.
 *
 * It is used instead of RCU because of patents that may not allow writing
 * an implementation not based on the Linux code (see
 * http://lists.lttng.org/pipermail/lttng-dev/2013-May/020305.html). As
 * patents expire, this module could be reworked to become a true RCU
 * implementation. In the mean time, the module interface was carefully
 * designed to be similar to RCU.
 *
 * TODO Gracefully handle large amounts of deferred works.
 */

#include <kern/assert.h>
#include <kern/condition.h>
#include <kern/cpumap.h>
#include <kern/evcnt.h>
#include <kern/init.h>
#include <kern/list.h>
#include <kern/llsync.h>
#include <kern/llsync_i.h>
#include <kern/macros.h>
#include <kern/mutex.h>
#include <kern/param.h>
#include <kern/printk.h>
#include <kern/spinlock.h>
#include <kern/sprintf.h>
#include <kern/stddef.h>
#include <kern/work.h>
#include <machine/cpu.h>

/*
 * Initial global checkpoint ID.
 *
 * Set to a high value to make sure overflows are correctly handled.
 */
#define LLSYNC_INITIAL_GCID ((unsigned int)-10)

/*
 * Number of pending works beyond which to issue a warning.
 */
#define LLSYNC_NR_PENDING_WORKS_WARN 10000

struct llsync_data llsync_data;
struct llsync_cpu_data llsync_cpu_data[MAX_CPUS];

struct llsync_waiter {
    struct work work;
    struct mutex lock;
    struct condition cond;
    int done;
};

void __init
llsync_setup(void)
{
    spinlock_init(&llsync_data.lock);
    work_queue_init(&llsync_data.queue0);
    work_queue_init(&llsync_data.queue1);
    evcnt_register(&llsync_data.ev_global_checkpoint,
                   "llsync_global_checkpoint");
    evcnt_register(&llsync_data.ev_periodic_checkin,
                   "llsync_periodic_checkin");
    evcnt_register(&llsync_data.ev_failed_periodic_checkin,
                   "llsync_failed_periodic_checkin");
    llsync_data.gcid.value = LLSYNC_INITIAL_GCID;
}

static void
llsync_process_global_checkpoint(void)
{
    struct work_queue queue;
    unsigned int nr_works;

    assert(cpumap_find_first(&llsync_data.pending_checkpoints) == -1);
    assert(llsync_data.nr_pending_checkpoints == 0);

    if (llsync_data.nr_registered_cpus == 0) {
        work_queue_concat(&llsync_data.queue1, &llsync_data.queue0);
        work_queue_init(&llsync_data.queue0);
    } else {
        cpumap_copy(&llsync_data.pending_checkpoints, &llsync_data.registered_cpus);
        llsync_data.nr_pending_checkpoints = llsync_data.nr_registered_cpus;
    }

    work_queue_transfer(&queue, &llsync_data.queue1);
    work_queue_transfer(&llsync_data.queue1, &llsync_data.queue0);
    work_queue_init(&llsync_data.queue0);
    nr_works = work_queue_nr_works(&queue);

    if (nr_works != 0) {
        llsync_data.nr_pending_works -= nr_works;
        work_queue_schedule(&queue, 0);
    }

    llsync_data.gcid.value++;
    evcnt_inc(&llsync_data.ev_global_checkpoint);
}

static void
llsync_commit_checkpoint(unsigned int cpu)
{
    int pending;

    pending = cpumap_test(&llsync_data.pending_checkpoints, cpu);

    if (!pending)
        return;

    cpumap_clear(&llsync_data.pending_checkpoints, cpu);
    llsync_data.nr_pending_checkpoints--;

    if (llsync_data.nr_pending_checkpoints == 0)
        llsync_process_global_checkpoint();
}

void
llsync_register(void)
{
    struct llsync_cpu_data *cpu_data;
    unsigned long flags;
    unsigned int cpu;

    cpu = cpu_id();
    cpu_data = llsync_get_cpu_data(cpu);

    spinlock_lock_intr_save(&llsync_data.lock, &flags);

    assert(!cpu_data->registered);
    cpu_data->registered = 1;
    cpu_data->gcid = llsync_data.gcid.value;

    assert(!cpumap_test(&llsync_data.registered_cpus, cpu));
    cpumap_set(&llsync_data.registered_cpus, cpu);
    llsync_data.nr_registered_cpus++;

    assert(!cpumap_test(&llsync_data.pending_checkpoints, cpu));

    if ((llsync_data.nr_registered_cpus == 1)
        && (llsync_data.nr_pending_checkpoints == 0))
        llsync_process_global_checkpoint();

    spinlock_unlock_intr_restore(&llsync_data.lock, flags);
}

void
llsync_unregister(void)
{
    struct llsync_cpu_data *cpu_data;
    unsigned long flags;
    unsigned int cpu;

    cpu = cpu_id();
    cpu_data = llsync_get_cpu_data(cpu);

    spinlock_lock_intr_save(&llsync_data.lock, &flags);

    assert(cpu_data->registered);
    cpu_data->registered = 0;

    assert(cpumap_test(&llsync_data.registered_cpus, cpu));
    cpumap_clear(&llsync_data.registered_cpus, cpu);
    llsync_data.nr_registered_cpus--;

    /*
     * Processor registration qualifies as a checkpoint. Since unregistering
     * a processor also disables commits until it's registered again, perform
     * one now.
     */
    llsync_commit_checkpoint(cpu);

    spinlock_unlock_intr_restore(&llsync_data.lock, flags);
}

void
llsync_report_periodic_event(void)
{
    struct llsync_cpu_data *cpu_data;
    unsigned int cpu, gcid;

    assert(!cpu_intr_enabled());
    assert(!thread_preempt_enabled());

    cpu = cpu_id();
    cpu_data = llsync_get_cpu_data(cpu);

    if (!cpu_data->registered)
        return;

    spinlock_lock(&llsync_data.lock);

    gcid = llsync_data.gcid.value;
    assert((gcid - cpu_data->gcid) <= 1);

    /*
     * If the local copy of the global checkpoint ID matches the true
     * value, the current processor has checked in.
     *
     * Otherwise, there were no checkpoint since the last global checkpoint.
     * Check whether this periodic event occurred during a read-side critical
     * section, and if not, trigger a checkpoint.
     */
    if (cpu_data->gcid == gcid)
        llsync_commit_checkpoint(cpu);
    else {
        if (thread_llsync_in_read_cs())
            evcnt_inc(&llsync_data.ev_failed_periodic_checkin);
        else {
            cpu_data->gcid = gcid;
            evcnt_inc(&llsync_data.ev_periodic_checkin);
            llsync_commit_checkpoint(cpu);
        }
    }

    spinlock_unlock(&llsync_data.lock);
}

void
llsync_defer(struct work *work)
{
    unsigned long flags;

    spinlock_lock_intr_save(&llsync_data.lock, &flags);

    work_queue_push(&llsync_data.queue0, work);
    llsync_data.nr_pending_works++;

    if (llsync_data.nr_pending_works == LLSYNC_NR_PENDING_WORKS_WARN)
        printk("llsync: warning: large number of pending works\n");

    spinlock_unlock_intr_restore(&llsync_data.lock, flags);
}

static void
llsync_signal(struct work *work)
{
    struct llsync_waiter *waiter;

    waiter = structof(work, struct llsync_waiter, work);

    mutex_lock(&waiter->lock);
    waiter->done = 1;
    condition_signal(&waiter->cond);
    mutex_unlock(&waiter->lock);
}

void
llsync_wait(void)
{
    struct llsync_waiter waiter;

    work_init(&waiter.work, llsync_signal);
    mutex_init(&waiter.lock);
    condition_init(&waiter.cond);
    waiter.done = 0;

    llsync_defer(&waiter.work);

    mutex_lock(&waiter.lock);

    while (!waiter.done)
        condition_wait(&waiter.cond, &waiter.lock);

    mutex_unlock(&waiter.lock);
}
