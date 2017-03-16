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

#ifndef _KERN_LLSYNC_I_H
#define _KERN_LLSYNC_I_H

#include <kern/assert.h>
#include <kern/cpumap.h>
#include <kern/macros.h>
#include <kern/param.h>
#include <kern/spinlock.h>
#include <kern/syscnt.h>
#include <kern/work.h>
#include <machine/cpu.h>

/*
 * Global data.
 *
 * The queue number matches the number of global checkpoints that occurred
 * since works contained in it were added. After two global checkpoints,
 * works are scheduled for processing.
 *
 * Interrupts must be disabled when acquiring the global data lock.
 */
struct llsync_data {
    struct spinlock lock;
    struct cpumap registered_cpus;
    unsigned int nr_registered_cpus;
    struct cpumap pending_checkpoints;
    unsigned int nr_pending_checkpoints;
    int no_warning;
    struct work_queue queue0;
    struct work_queue queue1;
    struct syscnt sc_global_checkpoints;
    struct syscnt sc_periodic_checkins;
    struct syscnt sc_failed_periodic_checkins;

    /*
     * Global checkpoint ID.
     *
     * This variable can be frequently accessed from many processors so :
     *  - reserve a whole cache line for it
     *  - apply optimistic accesses to reduce contention
     */
    struct {
        volatile unsigned int value __aligned(CPU_L1_SIZE);
    } gcid;
};

extern struct llsync_data llsync_data;

/*
 * Per-processor data.
 *
 * Every processor records whether it is registered and a local copy of the
 * global checkpoint ID, which is meaningless on unregistered processors.
 * The true global checkpoint ID is incremented when a global checkpoint occurs,
 * after which all the local copies become stale. Checking in synchronizes
 * the local copy of the global checkpoint ID.
 *
 * When works are deferred, they are initially added to a processor-local
 * queue. This queue is regularly flushed to the global data, an operation
 * that occurs every time a processor may commit a checkpoint. The downside
 * of this scalability optimization is that it introduces some additional
 * latency for works that are added to a processor queue between a flush and
 * a global checkpoint.
 *
 * Interrupts and preemption must be disabled on access.
 */
struct llsync_cpu_data {
    int registered;
    unsigned int gcid;
    struct work_queue queue0;
};

extern struct llsync_cpu_data llsync_cpu_data;

static inline struct llsync_cpu_data *
llsync_get_cpu_data(void)
{
    return cpu_local_ptr(llsync_cpu_data);
}

static inline void
llsync_checkin(void)
{
    struct llsync_cpu_data *cpu_data;
    unsigned int gcid;

    assert(!cpu_intr_enabled());
    assert(!thread_preempt_enabled());

    cpu_data = llsync_get_cpu_data();

    if (!cpu_data->registered) {
        assert(work_queue_nr_works(&cpu_data->queue0) == 0);
        return;
    }

    /*
     * The global checkpoint ID obtained might be obsolete here, in which
     * case a commit will not determine that a checkpoint actually occurred.
     * This should seldom happen.
     */
    gcid = llsync_data.gcid.value;
    assert((gcid - cpu_data->gcid) <= 1);
    cpu_data->gcid = gcid;
}

#endif /* _KERN_LLSYNC_I_H */
