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

#include <kern/error.h>
#include <kern/cpumap.h>
#include <kern/panic.h>
#include <kern/thread.h>
#include <kern/xcall.h>
#include <test/test.h>

static bool test_done;

static void
test_fn(void *arg)
{
    uintptr_t cpu;

    assert(thread_interrupted());

    cpu = (uintptr_t)arg;

    if (cpu != cpu_id()) {
        panic("invalid cpu");
    }

    printf("function called, running on cpu%u\n", cpu_id());
    test_done = true;
}

static void
test_once(unsigned int cpu)
{
    test_done = false;

    printf("cross-call: cpu%u -> cpu%u:\n", cpu_id(), cpu);
    xcall_call(test_fn, (void *)(uintptr_t)cpu, cpu);

    if (!test_done) {
        panic("test_done false");
    }
}

static void
test_run_cpu(void *arg)
{
    (void)arg;

    for (unsigned int i = 0; i < cpu_count(); i++) {
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
    int error;

    (void)arg;

    error = cpumap_create(&cpumap);
    error_check(error, "cpumap_create");

    for (unsigned int i = 0; i < cpu_count(); i++) {
        cpumap_zero(cpumap);
        cpumap_set(cpumap, i);
        snprintf(name, sizeof(name), THREAD_KERNEL_PREFIX "test_run/%u", i);
        thread_attr_init(&attr, name);
        thread_attr_set_cpumap(&attr, cpumap);
        error = thread_create(&thread, &attr, test_run_cpu, NULL);
        error_check(error, "thread_create");
        thread_join(thread);
    }

    cpumap_destroy(cpumap);

    printf("done\n");
}

void
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
