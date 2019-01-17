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
 * sleep queue, and one that broadcasts the sleep queue after making
 * sure all waiters are sleeping.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include <kern/error.h>
#include <kern/init.h>
#include <kern/log.h>
#include <kern/sleepq.h>
#include <kern/thread.h>
#include <test/test.h>

#define TEST_NR_WAITERS 2

#if TEST_NR_WAITERS < 2
#error "invalid number of waiters"
#endif /* TEST_NR_WAITERS < 2 */

static unsigned int test_dummy_sync_obj;

static struct thread *test_waiters[TEST_NR_WAITERS];

static void
test_wait(void *arg)
{
    struct sleepq *sleepq;

    (void)arg;

    sleepq = sleepq_lend(&test_dummy_sync_obj, false);
    sleepq_wait(sleepq, "test");
    sleepq_return(sleepq);
}

static void
test_broadcast(void *arg)
{
    struct sleepq *sleepq;

    (void)arg;

    for (size_t i = 0; i < ARRAY_SIZE(test_waiters); i++) {
        while (thread_state(test_waiters[i]) != THREAD_SLEEPING) {
            thread_delay(1, false);
        }
    }

    sleepq = sleepq_acquire(&test_dummy_sync_obj, false);

    if (!sleepq) {
        panic("test: unable to acquire sleep queue");
    }

    sleepq_broadcast(sleepq);

    sleepq_release(sleepq);

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
    int error;

    for (size_t i = 0; i < ARRAY_SIZE(test_waiters); i++) {
        snprintf(name, sizeof(name), THREAD_KERNEL_PREFIX "test_wait:%zu", i);
        thread_attr_init(&attr, name);
        error = thread_create(&test_waiters[i], &attr, test_wait, NULL);
        error_check(error, "thread_create");
    }

    thread_attr_init(&attr, THREAD_KERNEL_PREFIX "test_broadcast");
    thread_attr_set_detached(&attr);
    error = thread_create(NULL, &attr, test_broadcast, NULL);
    error_check(error, "thread_create");
}
