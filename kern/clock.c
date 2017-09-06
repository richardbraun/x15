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
 */

#include <stdio.h>
#include <stdint.h>

#include <kern/atomic.h>
#include <kern/clock.h>
#include <kern/clock_i.h>
#include <kern/init.h>
#include <kern/llsync.h>
#include <kern/percpu.h>
#include <kern/sref.h>
#include <kern/syscnt.h>
#include <kern/thread.h>
#include <kern/timer.h>
#include <kern/work.h>
#include <machine/boot.h>
#include <machine/cpu.h>

struct clock_cpu_data {
    struct syscnt sc_tick_intrs;
};

static struct clock_cpu_data clock_cpu_data __percpu;

union clock_global_time clock_global_time;

static inline void __init
clock_cpu_data_init(struct clock_cpu_data *cpu_data, unsigned int cpu)
{
    char name[SYSCNT_NAME_SIZE];

    snprintf(name, sizeof(name), "clock_tick_intrs/%u", cpu);
    syscnt_register(&cpu_data->sc_tick_intrs, name);
}

static int __init
clock_setup(void)
{
    for (unsigned int cpu = 0; cpu < cpu_count(); cpu++) {
        clock_cpu_data_init(percpu_ptr(clock_cpu_data, cpu), cpu);
    }

    return 0;
}

INIT_OP_DEFINE(clock_setup,
               INIT_OP_DEP(boot_setup_intr, true),
               INIT_OP_DEP(cpu_mp_probe, true),
               INIT_OP_DEP(syscnt_setup, true));

void clock_tick_intr(void)
{
    struct clock_cpu_data *cpu_data;

    assert(thread_check_intr_context());

    if (cpu_id() == 0) {
#ifdef ATOMIC_HAVE_64B_OPS

        atomic_add(&clock_global_time.ticks, 1, ATOMIC_RELAXED);

#else /* ATOMIC_HAVE_64B_OPS */

        union clock_global_time t;

        t.ticks = clock_global_time.ticks;
        t.ticks++;

        atomic_store(&clock_global_time.high2, t.high1, ATOMIC_RELAXED);
        atomic_store_release(&clock_global_time.low, t.low);
        atomic_store_release(&clock_global_time.high1, t.high1);

#endif /* ATOMIC_HAVE_64B_OPS */
    }

    timer_report_periodic_event();
    llsync_report_periodic_event();
    sref_report_periodic_event();
    work_report_periodic_event();
    thread_report_periodic_event();

    cpu_data = cpu_local_ptr(clock_cpu_data);
    syscnt_inc(&cpu_data->sc_tick_intrs);
}
