/*
 * Copyright (c) 2014 Richard Braun.
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
 * This is a simple test of the cross-call functionality. One thread is
 * created and bound to CPU 0. It makes two cross-calls, one on its local
 * processor, and another on a remote processor.
 */

#include <stddef.h>
#include <stdio.h>

#include <kern/error.h>
#include <kern/cpumap.h>
#include <kern/panic.h>
#include <kern/thread.h>
#include <kern/xcall.h>
#include <test/test.h>

static int test_done;

static void
test_fn(void *arg)
{
    (void)arg;

    assert(thread_interrupted());

    printf("function called, running on cpu%u\n", cpu_id());
    test_done = 1;
}

static void
test_once(unsigned int cpu)
{
    test_done = 0;

    printf("cross-call on cpu%u:\n", cpu);
    xcall_call(test_fn, NULL, cpu);

    if (!test_done) {
        panic("test_done false");
    }
}

static void
test_run(void *arg)
{
    (void)arg;

    test_once(0);
    test_once(1);
    printf("done\n");
}

void
test_setup(void)
{
    struct thread_attr attr;
    struct thread *thread;
    struct cpumap *cpumap;
    int error;

    error = cpumap_create(&cpumap);
    error_check(error, "cpumap_create");
    cpumap_zero(cpumap);
    cpumap_set(cpumap, 0);

    thread_attr_init(&attr, THREAD_KERNEL_PREFIX "test_run");
    thread_attr_set_detached(&attr);
    thread_attr_set_cpumap(&attr, cpumap);
    error = thread_create(&thread, &attr, test_run, NULL);
    error_check(error, "thread_create");

    cpumap_destroy(cpumap);
}
