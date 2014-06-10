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

#define LLSYNC_NR_PENDING_WORKS_WARN 10000

struct llsync_cpu llsync_cpus[MAX_CPUS];

/*
 * Global lock protecting the remaining module data.
 *
 * Interrupts must be disabled when acquiring this lock.
 */
static struct spinlock llsync_lock;

/*
 * Map of processors regularly checking in.
 */
static struct cpumap llsync_registered_cpus;
static unsigned int llsync_nr_registered_cpus;

/*
 * Map of processors for which a checkpoint commit is pending.
 *
 * To reduce contention, checking in only affects a single per-processor
 * cache line. Special events (currently the system timer interrupt only)
 * trigger checkpoint commits, which report the local state to this CPU
 * map, thereby acquiring the global lock.
 */
static struct cpumap llsync_pending_checkpoints;
static unsigned int llsync_nr_pending_checkpoints;

/*
 * Queues of deferred works.
 *
 * The queue number matches the number of global checkpoints that occurred
 * since works contained in it were added. After two global checkpoints,
 * works are scheduled for processing.
 */
static struct work_queue llsync_queue0;
static struct work_queue llsync_queue1;

/*
 * Number of works not yet scheduled for processing.
 *
 * Mostly unused, except for debugging.
 */
static unsigned long llsync_nr_pending_works;

struct llsync_waiter {
    struct work work;
    struct mutex lock;
    struct condition cond;
    int done;
};

void __init
llsync_setup(void)
{
    char name[EVCNT_NAME_SIZE];
    unsigned int cpu;

    spinlock_init(&llsync_lock);
    work_queue_init(&llsync_queue0);
    work_queue_init(&llsync_queue1);

    for (cpu = 0; cpu < cpu_count(); cpu++) {
        snprintf(name, sizeof(name), "llsync_reset/%u", cpu);
        evcnt_register(&llsync_cpus[cpu].ev_reset, name);
        snprintf(name, sizeof(name), "llsync_spurious_reset/%u", cpu);
        evcnt_register(&llsync_cpus[cpu].ev_spurious_reset, name);
    }
}

static void
llsync_reset_checkpoint_common(unsigned int cpu)
{
    assert(!cpumap_test(&llsync_pending_checkpoints, cpu));
    cpumap_set(&llsync_pending_checkpoints, cpu);
    llsync_cpus[cpu].checked = 0;
}

static void
llsync_process_global_checkpoint(unsigned int cpu)
{
    struct work_queue queue;
    unsigned int nr_works;
    int i;

    if (llsync_nr_registered_cpus == 0) {
        work_queue_concat(&llsync_queue1, &llsync_queue0);
        work_queue_init(&llsync_queue0);
    }

    work_queue_transfer(&queue, &llsync_queue1);
    work_queue_transfer(&llsync_queue1, &llsync_queue0);
    work_queue_init(&llsync_queue0);

    llsync_nr_pending_checkpoints = llsync_nr_registered_cpus;

    if (llsync_cpus[cpu].registered)
        llsync_reset_checkpoint_common(cpu);

    cpumap_for_each(&llsync_registered_cpus, i)
        if ((unsigned int)i != cpu)
            cpu_send_llsync_reset(i);

    nr_works = work_queue_nr_works(&queue);

    if (nr_works != 0) {
        llsync_nr_pending_works -= nr_works;
        work_queue_schedule(&queue, 0);
    }
}

static void
llsync_commit_checkpoint_common(unsigned int cpu)
{
    int pending;

    pending = cpumap_test(&llsync_pending_checkpoints, cpu);

    if (!pending)
        return;

    cpumap_clear(&llsync_pending_checkpoints, cpu);
    llsync_nr_pending_checkpoints--;

    if (llsync_nr_pending_checkpoints == 0)
        llsync_process_global_checkpoint(cpu);
}

void
llsync_register_cpu(unsigned int cpu)
{
    unsigned long flags;

    spinlock_lock_intr_save(&llsync_lock, &flags);

    assert(!llsync_cpus[cpu].registered);
    llsync_cpus[cpu].registered = 1;

    assert(!cpumap_test(&llsync_registered_cpus, cpu));
    cpumap_set(&llsync_registered_cpus, cpu);
    llsync_nr_registered_cpus++;

    assert(!cpumap_test(&llsync_pending_checkpoints, cpu));

    if ((llsync_nr_registered_cpus == 1)
        && (llsync_nr_pending_checkpoints == 0))
        llsync_process_global_checkpoint(cpu);

    spinlock_unlock_intr_restore(&llsync_lock, flags);
}

void
llsync_unregister_cpu(unsigned int cpu)
{
    unsigned long flags;

    spinlock_lock_intr_save(&llsync_lock, &flags);

    assert(llsync_cpus[cpu].registered);
    llsync_cpus[cpu].registered = 0;

    assert(cpumap_test(&llsync_registered_cpus, cpu));
    cpumap_clear(&llsync_registered_cpus, cpu);
    llsync_nr_registered_cpus--;

    /*
     * Processor registration qualifies as a checkpoint. Since unregistering
     * a processor also disables commits until it's registered again, perform
     * one now.
     */
    llsync_commit_checkpoint_common(cpu);

    spinlock_unlock_intr_restore(&llsync_lock, flags);
}

void
llsync_reset_checkpoint(unsigned int cpu)
{
    assert(!cpu_intr_enabled());

    spinlock_lock(&llsync_lock);

    evcnt_inc(&llsync_cpus[cpu].ev_reset);
    llsync_reset_checkpoint_common(cpu);

    /*
     * It may happen that this processor was registered at the time a global
     * checkpoint occurred, but unregistered itself before receiving the reset
     * interrupt. In this case, behave as if the reset request was received
     * before unregistering by immediately committing the local checkpoint.
     */
    if (!llsync_cpus[cpu].registered) {
        evcnt_inc(&llsync_cpus[cpu].ev_spurious_reset);
        llsync_commit_checkpoint_common(cpu);
    }

    spinlock_unlock(&llsync_lock);
}

void
llsync_commit_checkpoint(unsigned int cpu)
{
    assert(!cpu_intr_enabled());

    if (!(llsync_cpus[cpu].registered && llsync_cpus[cpu].checked))
        return;

    spinlock_lock(&llsync_lock);
    llsync_commit_checkpoint_common(cpu);
    spinlock_unlock(&llsync_lock);
}

void
llsync_defer(struct work *work)
{
    unsigned long flags;

    spinlock_lock_intr_save(&llsync_lock, &flags);

    work_queue_push(&llsync_queue0, work);
    llsync_nr_pending_works++;

    if (llsync_nr_pending_works == LLSYNC_NR_PENDING_WORKS_WARN)
        printk("llsync: warning: large number of pending works\n");

    spinlock_unlock_intr_restore(&llsync_lock, flags);
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
