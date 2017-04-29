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
 * This test module checks that the no-reference function of a scalable
 * reference counter is actually called when the number of references drops
 * to 0. An initial master thread creates a bunch of slave threads, more
 * than the number of processors to enforce migrations. These slaves wait
 * for the master to allocate a page for a test object with a scalable
 * reference counter. Once they receive the page, they manipulate the
 * counter until the master thread tells them to stop. The master thread
 * also manipulates the counter for a fixed number of iterations before
 * stopping the slaves. The master thread then joins all slaves to make
 * sure all of them have released their reference on the test object.
 * Finally, it releases the initial reference, at which point, the
 * no-reference function should be called.
 *
 * Notes: the number of loops must be large enough to allow many epochs
 * to occur.
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

#define NR_LOOPS (100UL * 1000 * 1000)

struct test_obj {
    struct sref_counter ref_counter;
};

static struct condition test_condition;
static struct mutex test_lock;
static struct test_obj *test_obj;
static volatile int test_stop;

static void
test_manipulate_counter(struct test_obj *obj)
{
    sref_counter_inc(&obj->ref_counter);
    thread_yield();
    sref_counter_dec(&obj->ref_counter);
    thread_yield();
}

static void
test_ref(void *arg)
{
    struct test_obj *obj;

    (void)arg;

    mutex_lock(&test_lock);

    printf("waiting for page\n");

    while (test_obj == NULL) {
        condition_wait(&test_condition, &test_lock);
    }

    obj = test_obj;

    mutex_unlock(&test_lock);

    printf("page received, manipulate reference counter\n");

    while (!test_stop) {
        test_manipulate_counter(obj);
    }

    printf("thread exiting\n");
}

static void
test_obj_noref(struct sref_counter *counter)
{
    struct test_obj *obj;

    obj = structof(counter, struct test_obj, ref_counter);
    vm_kmem_free(obj, sizeof(*obj));
    printf("0 references, page released\n");
    syscnt_info("sref_epoch");
    syscnt_info("sref_dirty_zero");
    syscnt_info("sref_true_zero");
}

static void
test_run(void *arg)
{
    char name[THREAD_NAME_SIZE];
    struct thread_attr attr;
    struct thread **threads;
    struct test_obj *obj;
    volatile unsigned long loop;
    unsigned int i, nr_threads;
    int error;

    (void)arg;

    nr_threads = cpu_count() + 1;
    threads = kmem_alloc(sizeof(*threads) * nr_threads);

    if (threads == NULL) {
        panic("kmem_alloc: %s", error_str(ERROR_NOMEM));
    }

    for (i = 0; i < nr_threads; i++) {
        snprintf(name, sizeof(name), THREAD_KERNEL_PREFIX "test_ref/%u", i);
        thread_attr_init(&attr, name);
        error = thread_create(&threads[i], &attr, test_ref, NULL);
        error_check(error, "thread_create");
    }

    printf("allocating page\n");
    obj = vm_kmem_alloc(sizeof(*obj));

    if (obj == NULL) {
        panic("vm_kmem_alloc: %s", error_str(ERROR_NOMEM));
    }

    sref_counter_init(&obj->ref_counter, NULL, test_obj_noref);

    printf("page allocated, 1 reference, publishing\n");

    mutex_lock(&test_lock);
    test_obj = obj;
    condition_broadcast(&test_condition);
    mutex_unlock(&test_lock);

    for (loop = 0; loop < NR_LOOPS; loop++) {
        test_manipulate_counter(obj);
    }

    printf("stopping test, wait for threads\n");
    test_stop = 1;

    for (i = 0; i < nr_threads; i++) {
        thread_join(threads[i]);
    }

    printf("releasing initial reference\n");
    sref_counter_dec(&obj->ref_counter);

    kmem_free(threads, sizeof(*threads) * nr_threads);
}

void
test_setup(void)
{
    struct thread_attr attr;
    struct thread *thread;
    int error;

    condition_init(&test_condition);
    mutex_init(&test_lock);

    thread_attr_init(&attr, THREAD_KERNEL_PREFIX "test_run");
    thread_attr_set_detached(&attr);
    error = thread_create(&thread, &attr, test_run, NULL);
    error_check(error, "thread_create");
}
