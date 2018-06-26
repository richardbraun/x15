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
 * Performance monitoring based on hardware performance counters.
 *
 * The hardware layer is represented by a performance monitoring unit (PMU),
 * which provides performance monitoring counters (PMCs).
 */

#ifndef KERN_PERFMON_H
#define KERN_PERFMON_H

#include <stdint.h>

#include <kern/init.h>
#include <kern/perfmon_types.h>
#include <kern/thread.h>

/*
 * IDs of generic performance monitoring events.
 */
#define PERFMON_EV_CYCLE            0
#define PERFMON_EV_REF_CYCLE        1
#define PERFMON_EV_INSTRUCTION      2
#define PERFMON_EV_CACHE_REF        3
#define PERFMON_EV_CACHE_MISS       4
#define PERFMON_EV_BRANCH           5
#define PERFMON_EV_BRANCH_MISS      6
#define PERFMON_NR_GENERIC_EVENTS   7

/*
 * Event flags.
 */
#define PERFMON_EF_KERN     0x1 /* Monitor events in kernel mode */
#define PERFMON_EF_USER     0x2 /* Monitor events in user mode */
#define PERFMON_EF_RAW      0x4 /* Raw event ID, generic if unset */

/*
 * Performance monitoring operations.
 *
 * This is a public structure.
 *
 * All operations are either global but serialized by the caller, or
 * processor-local and called with interrupts and preemption disabled.
 *
 * If the hardware doesn't efficiently support overflow interrupts, the
 * handler must be set to NULL, making the perfmon module perdiocally
 * check the raw value of the hardware counters.
 */
struct perfmon_dev_ops {
    /*
     * Convert a generic event ID into a raw event ID.
     *
     * Global operation.
     */
    int (*translate)(unsigned int *raw_event_idp, unsigned int event_id);

    /*
     * Allocate a performance monitoring counter globally for the given
     * raw event ID, and return the counter ID through the given pointer.
     * The driver may return any PMC ID, as long as it uniquely identifies
     * the underlying counter. The PMC index is passed when reporting
     * overflows, if using a custom overflow interrupt handler.
     *
     * Global operation.
     */
    int (*alloc)(unsigned int *pmc_idp, unsigned int pmc_index,
                 unsigned int raw_event_id);

    /*
     * Free an allocated performance monitoring counter.
     *
     * Global operation.
     */
    void (*free)(unsigned int pmc_id);

    /*
     * Start a performance monitoring counter for the given raw event ID.
     *
     * Processor-local operation.
     */
    void (*start)(unsigned int pmc_id, unsigned int raw_event_id);

    /*
     * Stop a performance monitoring counter.
     *
     * Processor-local operation.
     */
    void (*stop)(unsigned int pmc_id);

    /*
     * Read the value of a performance monitoring counter.
     *
     * Processor-local operation.
     */
    uint64_t (*read)(unsigned int pmc_id);

    /*
     * Custom overflow interrupt handler.
     *
     * Processor-local operation.
     */
    void (*handle_overflow_intr)(void);
};

/*
 * Performance monitoring device.
 *
 * This is a public structure.
 *
 * The PMC width is expressed in bits.
 *
 * If the driver doesn't provide an overflow interrupt handler, it may set
 * the poll interval, in ticks, to a duration that safely allows the detection
 * of a single overflow. A value of 0 lets the perfmon module compute a poll
 * interval itself.
 */
struct perfmon_dev {
    const struct perfmon_dev_ops *ops;
    unsigned int pmc_width;
    uint64_t poll_interval;
};

/*
 * Performance monitoring thread data.
 */
struct perfmon_td;

/*
 * Performance monitoring event.
 *
 * An event describes a single, well-defined hardware condition and tracks
 * its occurrences over a period of time.
 */
struct perfmon_event;

/*
 * Initialize thread-specific data.
 */
void perfmon_td_init(struct perfmon_td *td);

/*
 * Load/unload events attached to a thread on the current processor.
 *
 * These functions should only be used by the scheduler on a context switch.
 * Interrupts and preemption must be disabled when calling these functions.
 */
void perfmon_td_load(struct perfmon_td *td);
void perfmon_td_unload(struct perfmon_td *td);

/*
 * Initialize an event.
 */
int perfmon_event_init(struct perfmon_event *event, unsigned int id,
                       unsigned int flags);

/*
 * Attach/detach an event to/from a thread or a processor.
 *
 * Attaching an event allocates hardware resources and enables monitoring.
 * The number of occurrences for the given event is reset.
 *
 * An event can only be attached to one thread or processor at a time.
 */
int perfmon_event_attach(struct perfmon_event *event, struct thread *thread);
int perfmon_event_attach_cpu(struct perfmon_event *event, unsigned int cpu);
int perfmon_event_detach(struct perfmon_event *event);

/*
 * Obtain the number of occurrences of an event.
 */
uint64_t perfmon_event_read(struct perfmon_event *event);

/*
 * Register a PMU device.
 *
 * Currently, there can only be a single system-wide PMU device, which
 * assumes the driver is the same for all processors.
 */
void perfmon_register(struct perfmon_dev *dev);

/*
 * Handle an overflow interrupt.
 *
 * This function must be called in interrupt context.
 */
void perfmon_overflow_intr(void);

/*
 * Report a PMC overflow.
 *
 * This function is intended to be used by PMU drivers using a custom
 * overflow interrupt handler.
 *
 * This function must be called in interrupt context.
 */
void perfmon_report_overflow(unsigned int pmc_index);

/*
 * This init operation provides :
 *  - PMU device registration
 */
INIT_OP_DECLARE(perfmon_bootstrap);

#endif /* KERN_PERFMON_H */
