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
 * This test checks the behavior of performance monitoring on a CPU.
 * It creates a group with two events, cycle and instruction, and attaches
 * that group to CPU1, where a thread is bound and runs a tight loop to
 * make sure the target CPU is never idle. After some time, the measurement
 * stops and values are reported.
 */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <kern/atomic.h>
#include <kern/clock.h>
#include <kern/cpumap.h>
#include <kern/error.h>
#include <kern/list.h>
#include <kern/log.h>
#include <kern/panic.h>
#include <kern/perfmon.h>
#include <kern/thread.h>
#include <machine/cpu.h>
#include <test/test.h>

#define TEST_WAIT_DELAY_MS 1000

/*
 * Using another CPU than the BSP as the monitored CPU checks that PMUs are
 * correctly initialized on APs.
 */
#define TEST_CONTROL_CPU    0
#define TEST_MONITORED_CPU  (TEST_CONTROL_CPU + 1)
#define TEST_MIN_CPUS       (TEST_MONITORED_CPU + 1)

#define TEST_EVENT_NAME_MAX_SIZE 32

struct test_event {
    struct list node;
    struct perfmon_event pm_event;
    char name[TEST_EVENT_NAME_MAX_SIZE];
};

struct test_group {
    struct list events;
};

static unsigned int test_run_stop;

static void
test_wait(void)
{
    thread_delay(clock_ticks_from_ms(TEST_WAIT_DELAY_MS), false);
}

static void
test_event_init(struct test_event *event, unsigned int id, const char *name)
{
    int error;

    error = perfmon_event_init(&event->pm_event, id, PERFMON_EF_KERN);
    error_check(error, "perfmon_event_init");
    strlcpy(event->name, name, sizeof(event->name));
}

static void
test_event_report(struct test_event *event)
{
    uint64_t count;
    int error;

    count = perfmon_event_read(&event->pm_event);
    error = (count == 0) ? EINVAL : 0;
    error_check(error, __func__);
    log_info("test: %s: %llu", event->name, (unsigned long long)count);
}

static void
test_event_attach_cpu(struct test_event *event, unsigned int cpu)
{
    int error;

    error = perfmon_event_attach_cpu(&event->pm_event, cpu);
    error_check(error, "perfmon_event_attach_cpu");
}

static void
test_event_detach(struct test_event *event)
{
    int error;

    error = perfmon_event_detach(&event->pm_event);
    error_check(error, "perfmon_event_detach");
}

static void
test_group_init(struct test_group *group)
{
    list_init(&group->events);
}

static void
test_group_add(struct test_group *group, struct test_event *event)
{
    list_insert_tail(&group->events, &event->node);
}

static void
test_group_attach_cpu(struct test_group *group, unsigned int cpu)
{
    struct test_event *event;

    list_for_each_entry(&group->events, event, node) {
        test_event_attach_cpu(event, cpu);
    }
}

static void
test_group_detach(struct test_group *group)
{
    struct test_event *event;

    list_for_each_entry(&group->events, event, node) {
        test_event_detach(event);
    }
}

static void
test_group_report(struct test_group *group)
{
    struct test_event *event;

    list_for_each_entry(&group->events, event, node) {
        test_event_report(event);
    }
}

static void
test_run(void *arg)
{
    unsigned int stop;

    (void)arg;

    do {
        stop = atomic_load(&test_run_stop, ATOMIC_RELAXED);
    } while (!stop);
}

static void
test_control(void *arg)
{
    struct test_event cycle, instruction;
    struct test_group group;
    struct thread *thread;

    thread = arg;

    test_event_init(&cycle, PERFMON_EV_CYCLE, "cycle");
    test_event_init(&instruction, PERFMON_EV_INSTRUCTION, "instruction");
    test_group_init(&group);
    test_group_add(&group, &cycle);
    test_group_add(&group, &instruction);
    test_group_attach_cpu(&group, TEST_MONITORED_CPU);
    test_wait();
    test_group_report(&group);
    test_wait();
    test_group_detach(&group);
    test_group_report(&group);

    atomic_store(&test_run_stop, 1, ATOMIC_RELAXED);
    thread_join(thread);
    log_info("test: done");
}

void
test_setup(void)
{
    struct thread *thread;
    struct thread_attr attr;
    struct cpumap *cpumap;
    int error;

    if (cpu_count() < TEST_MIN_CPUS) {
        panic("test: %u processors required", TEST_MIN_CPUS);
    }

    error = cpumap_create(&cpumap);
    error_check(error, "cpumap_create");

    thread_attr_init(&attr, THREAD_KERNEL_PREFIX "test_run");
    cpumap_zero(cpumap);
    cpumap_set(cpumap, TEST_MONITORED_CPU);
    thread_attr_set_cpumap(&attr, cpumap);
    error = thread_create(&thread, &attr, test_run, NULL);
    error_check(error, "thread_create");

    thread_attr_init(&attr, THREAD_KERNEL_PREFIX "test_control");
    thread_attr_set_detached(&attr);
    cpumap_zero(cpumap);
    cpumap_set(cpumap, TEST_CONTROL_CPU);
    thread_attr_set_cpumap(&attr, cpumap);
    error = thread_create(NULL, &attr, test_control, thread);
    error_check(error, "thread_create");

    cpumap_destroy(cpumap);
}
