/*
 * Copyright (c) 2014-2018 Remy Noel.
 * Copyright (c) 2014-2018 Richard Braun.
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
 * Isolated type definitions used to avoid inclusion circular dependencies.
 */

#ifndef KERN_PERFMON_TYPES_H
#define KERN_PERFMON_TYPES_H

#ifdef CONFIG_PERFMON

#include <stdbool.h>
#include <stdint.h>

#include <kern/spinlock_types.h>

/*
 * Maximum number of supported hardware counters.
 */
#define PERFMON_MAX_PMCS CONFIG_PERFMON_MAX_PMCS

/*
 * Performance monitoring event.
 *
 * An event may be unattached, attached to a thread, or attached to a CPU.
 * When it is loaded, the current value of the underlying PMC is saved.
 * When it is updated, the delta between the current and saved PMC values
 * is added to the event value.
 */
struct perfmon_event {
    struct spinlock lock;
    unsigned int flags;
    unsigned int id;
    uint64_t pmc_value;
    uint64_t value;

    union {
        struct thread *thread;
        unsigned int cpu;
    };

    unsigned int pmc_index;
};

/*
 * Per-thread performance monitoring counter.
 *
 * Per-thread PMCs are indexed the same way as global PMCs.
 *
 * A per-thread PMC is referenced when an event is attached to a thread.
 * The PMC may only be loaded if the thread is running on a processor,
 * as a result of an event being attached to the thread, or the thread
 * being dispatched by the scheduler. Note that this allows a transient
 * state to be seen where a per-thread PMC is both unused and loaded.
 * This happens after detaching an event from a thread, resulting in
 * the underlying per-thread PMC to become unused, but if the thread
 * is running concurrently, the counter is still loaded. The implementation
 * resolves the situation by unloading the counter, which is either
 * done by an explicit unload cross-call, or when the scheduler preempts
 * the thread and unloads its thread data.
 *
 * When a per-thread PMC is loaded, the current value of the underlying
 * PMC is saved, and when it's updated, the delta between the current
 * and saved PMC values is added to the per-thread PMC value.
 */
struct perfmon_td_pmc {
    unsigned int nr_refs;
    bool loaded;
    unsigned int pmc_id;
    unsigned int raw_event_id;
    uint64_t cpu_pmc_value;
    uint64_t value;
};

/*
 * Per-thread performance monitoring data.
 *
 * Interrupts must be disabled when locking thread data.
 */
struct perfmon_td {
    struct spinlock lock;
    struct perfmon_td_pmc pmcs[PERFMON_MAX_PMCS];
};

#endif /* CONFIG_PERFMON */

#endif /* KERN_PERFMON_TYPES_H */
