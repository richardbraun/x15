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
 * This test checks the behavior of performance monitoring on a thread.
 * It creates a group with a single event, cycle, and attaches that group to
 * a runner thread. Two checks are then performed :
 *  - the first makes sure the number of cycles changes when the runner
 *    thread is running
 *  - the second makes sure the number of cycles doesn't change when the
 *    runner thread is sleeping
 *
 * Another group with a cycle event is created and attached to CPU0 to make
 * sure that a shared event is correctly handled, and the runner thread is
 * bound to CPU0 to force sharing. A third thread is created to fill CPU0
 * time with cycles so that the cycle counter of the CPU-attached group
 * changes while the runner thread is sleeping.
 */

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include <kern/atomic.h>
#include <kern/clock.h>
#include <kern/condition.h>
#include <kern/cpumap.h>
#include <kern/error.h>
#include <kern/kmem.h>
#include <kern/list.h>
#include <kern/log.h>
#include <kern/mutex.h>
#include <kern/panic.h>
#include <kern/perfmon.h>
#include <kern/thread.h>
#include <test/test.h>

#define TEST_WAIT_DELAY_MS 1000

#define TEST_EVENT_NAME_MAX_SIZE 32

struct test_event {
    struct list node;
    struct perfmon_event pm_event;
    uint64_t last_value;
    char name[TEST_EVENT_NAME_MAX_SIZE];
};

struct test_group {
    struct list events;
};

enum test_state {
    TEST_STATE_RUNNING,
    TEST_STATE_SUSPENDED,
    TEST_STATE_TERMINATED,
};

static struct condition test_condition;
static struct mutex test_mutex;
static enum test_state test_state;

static void
test_wait(void)
{
    log_info("test: controller waiting");
    thread_delay(clock_ticks_from_ms(TEST_WAIT_DELAY_MS), false);
    log_info("test: controller resuming");
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
test_event_attach(struct test_event *event, struct thread *thread)
{
    int error;

    error = perfmon_event_attach(&event->pm_event, thread);
    error_check(error, "perfmon_event_attach");
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

static uint64_t
test_event_read(struct test_event *event)
{
    uint64_t value;

    value = perfmon_event_read(&event->pm_event);
    log_info("test: %s: %llu", event->name, (unsigned long long)value);
    return value;
}

static void
test_event_save(struct test_event *event)
{
    event->last_value = test_event_read(event);
}

static void
test_event_check(struct test_event *event, bool change_expected)
{
    uint64_t value;
    bool changed;

    value = test_event_read(event);
    changed = (value != event->last_value);

    if (changed != change_expected) {
        panic("test: invalid value");
    }

    event->last_value = value;
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
test_group_attach(struct test_group *group, struct thread *thread)
{
    struct test_event *event;

    list_for_each_entry(&group->events, event, node) {
        test_event_attach(event, thread);
    }
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
test_group_save(struct test_group *group)
{
    struct test_event *event;

    list_for_each_entry(&group->events, event, node) {
        test_event_save(event);
    }
}

static void
test_group_check(struct test_group *group, bool change_expected)
{
    struct test_event *event;

    list_for_each_entry(&group->events, event, node) {
        test_event_check(event, change_expected);
    }
}

static void
test_run(void *arg)
{
    bool report;

    (void)arg;

    report = true;

    mutex_lock(&test_mutex);

    while (test_state != TEST_STATE_TERMINATED) {
        if (test_state == TEST_STATE_SUSPENDED) {
            log_info("test: runner suspended");
            report = true;
            condition_wait(&test_condition, &test_mutex);
        } else {
            mutex_unlock(&test_mutex);

            if (report) {
                log_info("test: runner running");
                report = false;
            }

            mutex_lock(&test_mutex);
        }
    }

    mutex_unlock(&test_mutex);
}

static void
test_fill(void *arg)
{
    enum test_state state;

    (void)arg;

    do {
        state = atomic_load(&test_state, ATOMIC_RELAXED);
    } while (state != TEST_STATE_TERMINATED);
}

static void
test_wait_state(const struct thread *thread, unsigned short state)
{
    for (;;) {
        if (thread_state(thread) == state) {
            break;
        }

        thread_delay(1, false);
    }
}

static void
test_resume(struct thread *thread)
{
    test_wait_state(thread, THREAD_SLEEPING);

    mutex_lock(&test_mutex);
    assert(test_state == TEST_STATE_SUSPENDED);
    atomic_store(&test_state, TEST_STATE_RUNNING, ATOMIC_RELAXED);
    condition_signal(&test_condition);
    mutex_unlock(&test_mutex);

    test_wait_state(thread, THREAD_RUNNING);
}

static void
test_suspend(struct thread *thread)
{
    test_wait_state(thread, THREAD_RUNNING);

    mutex_lock(&test_mutex);
    assert(test_state == TEST_STATE_RUNNING);
    atomic_store(&test_state, TEST_STATE_SUSPENDED, ATOMIC_RELAXED);
    mutex_unlock(&test_mutex);

    test_wait_state(thread, THREAD_SLEEPING);
}

static void
test_terminate(void)
{
    mutex_lock(&test_mutex);
    test_state = TEST_STATE_TERMINATED;
    condition_signal(&test_condition);
    mutex_unlock(&test_mutex);
}

static void
test_control(void *arg)
{
    struct test_event thread_cycle, cpu_cycle;
    struct test_group thread_group, cpu_group;
    struct thread *runner;

    runner = arg;

    test_event_init(&thread_cycle, PERFMON_EV_CYCLE, "thread_cycle");
    test_group_init(&thread_group);
    test_group_add(&thread_group, &thread_cycle);

    test_event_init(&cpu_cycle, PERFMON_EV_CYCLE, "cpu_cycle");
    test_group_init(&cpu_group);
    test_group_add(&cpu_group, &cpu_cycle);

    test_group_attach(&thread_group, runner);
    test_group_attach_cpu(&cpu_group, 0);

    test_group_save(&thread_group);
    test_group_save(&cpu_group);
    test_resume(runner);
    test_wait();
    test_suspend(runner);
    test_group_check(&thread_group, true);
    test_group_check(&cpu_group, true);
    test_wait();
    test_group_check(&thread_group, false);
    test_group_check(&cpu_group, true);
    test_terminate();

    test_group_detach(&cpu_group);
    test_group_detach(&thread_group);

    thread_join(runner);
    log_info("test: done");
}

void
test_setup(void)
{
    struct thread_attr attr;
    struct thread *runner;
    struct cpumap *cpumap;
    int error;

    condition_init(&test_condition);
    mutex_init(&test_mutex);
    test_state = TEST_STATE_SUSPENDED;

    error = cpumap_create(&cpumap);
    error_check(error, "cpumap_create");

    cpumap_zero(cpumap);
    cpumap_set(cpumap, 0);

    thread_attr_init(&attr, THREAD_KERNEL_PREFIX "test_run");
    thread_attr_set_cpumap(&attr, cpumap);
    error = thread_create(&runner, &attr, test_run, NULL);
    error_check(error, "thread_create");

    thread_attr_init(&attr, THREAD_KERNEL_PREFIX "test_fill");
    thread_attr_set_detached(&attr);
    thread_attr_set_cpumap(&attr, cpumap);
    thread_attr_set_priority(&attr, THREAD_SCHED_FS_PRIO_MIN);
    error = thread_create(NULL, &attr, test_fill, NULL);
    error_check(error, "thread_create");

    thread_attr_init(&attr, THREAD_KERNEL_PREFIX "test_control");
    thread_attr_set_detached(&attr);
    error = thread_create(NULL, &attr, test_control, runner);
    error_check(error, "thread_create");

    cpumap_destroy(cpumap);
}
