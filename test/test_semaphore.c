/*
 * Copyright (c) 2019 Richard Braun.
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
 * This test creates a number of threads (at least 2) which wait on a
 * semaphore, and one that posts the semaphore as many times as there
 * are threads. All threads are bound to the same processor, and posts
 * are performed with preemption disabled, to guarantee they occur
 * back-to-back in order to make sure that they're not missed.
 */

#include <stddef.h>
#include <stdio.h>

#include <kern/cpumap.h>
#include <kern/error.h>
#include <kern/log.h>
#include <kern/macros.h>
#include <kern/semaphore.h>
#include <kern/thread.h>
#include <test/test.h>

#define TEST_NR_WAITERS 2

#if TEST_NR_WAITERS < 2
#error "invalid number of waiters"
#endif /* TEST_NR_WAITERS < 2 */

static struct semaphore test_semaphore;

static struct thread *test_waiters[TEST_NR_WAITERS];

static void
test_wait(void *arg)
{
    (void)arg;

    semaphore_wait(&test_semaphore);
}

static void
test_post(void *arg)
{
    int error;

    (void)arg;

    for (size_t i = 0; i < ARRAY_SIZE(test_waiters); i++) {
        while (thread_state(test_waiters[i]) != THREAD_SLEEPING) {
            thread_delay(1, false);
        }
    }

    thread_preempt_disable();

    for (size_t i = 0; i < ARRAY_SIZE(test_waiters); i++) {
        error = semaphore_post(&test_semaphore);
        error_check(error, "semaphore_post");
    }

    thread_preempt_enable();

    for (size_t i = 0; i < ARRAY_SIZE(test_waiters); i++) {
        thread_join(test_waiters[i]);
    }

    log_info("test: done");
}

void __init
test_setup(void)
{
    char name[THREAD_NAME_SIZE];
    struct thread_attr attr;
    struct cpumap *cpumap;
    int error;

    semaphore_init(&test_semaphore, 0, TEST_NR_WAITERS);

    error = cpumap_create(&cpumap);
    error_check(error, "cpumap_create");
    cpumap_zero(cpumap);
    cpumap_set(cpumap, 0);

    for (size_t i = 0; i < ARRAY_SIZE(test_waiters); i++) {
        snprintf(name, sizeof(name), THREAD_KERNEL_PREFIX "test_wait:%zu", i);
        thread_attr_init(&attr, name);
        thread_attr_set_cpumap(&attr, cpumap);
        error = thread_create(&test_waiters[i], &attr, test_wait, NULL);
        error_check(error, "thread_create");
    }

    thread_attr_init(&attr, THREAD_KERNEL_PREFIX "test_post");
    thread_attr_set_detached(&attr);
    thread_attr_set_cpumap(&attr, cpumap);
    error = thread_create(NULL, &attr, test_post, NULL);
    error_check(error, "thread_create");
}
