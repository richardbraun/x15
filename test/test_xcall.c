/*
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
 * This test creates a thread that tests cross-calls for all combinations
 * of processors. This thread sequentially creates other threads that are
 * bound to a single processor, and perform cross-calls to all processors,
 * including the local one.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include <kern/cpumap.h>
#include <kern/error.h>
#include <kern/init.h>
#include <kern/log.h>
#include <kern/panic.h>
#include <kern/thread.h>
#include <kern/xcall.h>
#include <test/test.h>

struct test_data {
    unsigned int cpu;
    bool done;
};

static void
test_fn(void *arg)
{
    struct test_data *data;

    assert(thread_interrupted());

    data = arg;

    if (data->cpu != cpu_id()) {
        panic("test: invalid cpu");
    }

    log_info("function called, running on cpu%u\n", cpu_id());
    data->done = true;
}

static void
test_once(unsigned int cpu)
{
    struct test_data data;

    data.cpu = cpu;
    data.done = false;

    log_info("cross-call: cpu%u -> cpu%u:\n", cpu_id(), cpu);
    xcall_call(test_fn, &data, cpu);

    if (!data.done) {
        panic("test: xcall failed");
    }
}

static void
test_run_cpu(void *arg)
{
    (void)arg;

    for (unsigned int i = (cpu_count() - 1); i < cpu_count(); i--) {
        test_once(i);
    }
}

static void
test_run(void *arg)
{
    char name[THREAD_NAME_SIZE];
    struct thread_attr attr;
    struct thread *thread;
    struct cpumap *cpumap;
    unsigned int cpu;
    int error;

    (void)arg;

    error = cpumap_create(&cpumap);
    error_check(error, "cpumap_create");

    for (unsigned int i = 0; i < cpu_count(); i++) {
        /*
         * Send IPIs from CPU 1 first, in order to better trigger any
         * initialization race that may prevent correct IPI transmission.
         * This assumes CPUs are initialized sequentially, and that CPU 1
         * may have finished initialization much earlier than the last CPU.
         * CPU 0 isn't used since it's the one normally initializing remote
         * CPUs.
         */
        cpu = (1 + i) % cpu_count();

        cpumap_zero(cpumap);
        cpumap_set(cpumap, cpu);
        snprintf(name, sizeof(name), THREAD_KERNEL_PREFIX "test_run/%u", cpu);
        thread_attr_init(&attr, name);
        thread_attr_set_cpumap(&attr, cpumap);
        error = thread_create(&thread, &attr, test_run_cpu, NULL);
        error_check(error, "thread_create");
        thread_join(thread);
    }

    cpumap_destroy(cpumap);

    log_info("done\n");
}

void __init
test_setup(void)
{
    struct thread_attr attr;
    struct thread *thread;
    int error;

    thread_attr_init(&attr, THREAD_KERNEL_PREFIX "test_run");
    thread_attr_set_detached(&attr);
    error = thread_create(&thread, &attr, test_run, NULL);
    error_check(error, "thread_create");
}
