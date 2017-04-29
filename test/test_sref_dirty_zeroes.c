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
 * The purpose of this test module is to produce dirty zeroes and make
 * sure they're correctly processed. It is a stress test that never ends,
 * except on failure. Two threads are created. The first increments a
 * scalable reference counter, then signals the second that it can decrement
 * it. Since these threads are likely to run on different processors, a
 * good amount of dirty zeroes should be produced, as reported by regularly
 * printing the relevant event counters. Since the true number of references
 * can never drop to 0, the no-reference function should never be called,
 * and panics if it is.
 */

#include <stddef.h>
#include <stdio.h>

#include <kern/condition.h>
#include <kern/error.h>
#include <kern/kmem.h>
#include <kern/macros.h>
#include <kern/mutex.h>
#include <kern/panic.h>
#include <kern/sref.h>
#include <kern/syscnt.h>
#include <kern/thread.h>
#include <test/test.h>
#include <vm/vm_kmem.h>

static struct condition test_condition;
static struct mutex test_lock;
static struct sref_counter test_counter;
static unsigned long test_transient_ref;

static void
test_inc(void *arg)
{
    volatile unsigned long i;
    (void)arg;

    for (;;) {
        for (i = 0; i < 1000000; i++) {
            sref_counter_inc(&test_counter);

            mutex_lock(&test_lock);
            test_transient_ref++;
            condition_signal(&test_condition);

            while (test_transient_ref != 0) {
                condition_wait(&test_condition, &test_lock);
            }

            mutex_unlock(&test_lock);
        }

        printf("counter global value: %lu\n", test_counter.value);
        syscnt_info("sref_epoch");
        syscnt_info("sref_dirty_zero");
        syscnt_info("sref_true_zero");
    }
}

static void
test_dec(void *arg)
{
    (void)arg;

    for (;;) {
        mutex_lock(&test_lock);

        while (test_transient_ref == 0) {
            condition_wait(&test_condition, &test_lock);
        }

        test_transient_ref--;
        condition_signal(&test_condition);
        mutex_unlock(&test_lock);

        sref_counter_dec(&test_counter);
    }
}

static void
test_noref(struct sref_counter *counter)
{
    (void)counter;
    panic("0 references, page released\n");
}

void
test_setup(void)
{
    struct thread_attr attr;
    struct thread *thread;
    int error;

    condition_init(&test_condition);
    mutex_init(&test_lock);

    sref_counter_init(&test_counter, NULL, test_noref);
    test_transient_ref = 0;

    thread_attr_init(&attr, THREAD_KERNEL_PREFIX "test_inc");
    thread_attr_set_detached(&attr);
    error = thread_create(&thread, &attr, test_inc, NULL);
    error_check(error, "thread_create");

    thread_attr_init(&attr, THREAD_KERNEL_PREFIX "test_dec");
    thread_attr_set_detached(&attr);
    error = thread_create(&thread, &attr, test_dec, NULL);
    error_check(error, "thread_create");
}
