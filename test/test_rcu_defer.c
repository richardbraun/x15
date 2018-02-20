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
 * This test module is a stress test, expected to never terminate, of the
 * work deferring functionality of the rcu module. It creates three
 * threads, a producer, a consumer, and a reader. The producer allocates
 * a page and writes it. It then transfers the page to the consumer, using
 * the rcu interface to update the global page pointer. Once at the
 * consumer, the rcu interface is used to defer the release of the page.
 * Concurrently, the reader accesses the page and checks its content when
 * available. These accesses are performed inside a read-side critical
 * section and should therefore never fail.
 *
 * Each thread regularly prints a string to report that it's making progress.
 */

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <kern/condition.h>
#include <kern/cpumap.h>
#include <kern/error.h>
#include <kern/kmem.h>
#include <kern/macros.h>
#include <kern/mutex.h>
#include <kern/panic.h>
#include <kern/rcu.h>
#include <kern/thread.h>
#include <kern/work.h>
#include <machine/page.h>
#include <test/test.h>
#include <vm/vm_kmem.h>

#define TEST_LOOPS_PER_PRINT 100000

struct test_pdsc {
    struct work work;
    void *addr;
};

#define TEST_VALIDATION_BYTE 0xab

static struct mutex test_lock;
static struct condition test_condition;
static struct test_pdsc *test_pdsc;

static struct kmem_cache test_pdsc_cache;

static void
test_alloc(void *arg)
{
    struct test_pdsc *pdsc;
    unsigned long nr_loops;

    (void)arg;

    nr_loops = 0;

    mutex_lock(&test_lock);

    for (;;) {
        while (test_pdsc != NULL) {
            condition_wait(&test_condition, &test_lock);
        }

        pdsc = kmem_cache_alloc(&test_pdsc_cache);

        if (pdsc != NULL) {
            pdsc->addr = vm_kmem_alloc(PAGE_SIZE);

            if (pdsc->addr != NULL) {
                memset(pdsc->addr, TEST_VALIDATION_BYTE, PAGE_SIZE);
            }
        }

        rcu_store_ptr(test_pdsc, pdsc);
        condition_signal(&test_condition);

        if ((nr_loops % TEST_LOOPS_PER_PRINT) == 0) {
            printf("alloc ");
        }

        nr_loops++;
    }
}

static void
test_deferred_free(struct work *work)
{
    struct test_pdsc *pdsc;

    pdsc = structof(work, struct test_pdsc, work);

    if (pdsc->addr != NULL) {
        vm_kmem_free(pdsc->addr, PAGE_SIZE);
    }

    kmem_cache_free(&test_pdsc_cache, pdsc);
}

static void
test_free(void *arg)
{
    struct test_pdsc *pdsc;
    unsigned long nr_loops;

    (void)arg;

    nr_loops = 0;

    mutex_lock(&test_lock);

    for (;;) {
        while (test_pdsc == NULL) {
            condition_wait(&test_condition, &test_lock);
        }

        pdsc = test_pdsc;
        rcu_store_ptr(test_pdsc, NULL);

        if (pdsc != NULL) {
            work_init(&pdsc->work, test_deferred_free);
            rcu_defer(&pdsc->work);
        }

        condition_signal(&test_condition);

        if ((nr_loops % TEST_LOOPS_PER_PRINT) == 0) {
            printf("free ");
        }

        nr_loops++;
    }
}

static void
test_read(void *arg)
{
    const struct test_pdsc *pdsc;
    const unsigned char *s;
    unsigned long nr_loops;

    (void)arg;

    nr_loops = 0;

    for (;;) {
        rcu_read_enter();

        pdsc = rcu_load_ptr(test_pdsc);

        if (pdsc != NULL) {
            s = (const unsigned char *)pdsc->addr;

            if (s != NULL) {
                for (unsigned int i = 0; i < PAGE_SIZE; i++) {
                    if (s[i] != TEST_VALIDATION_BYTE) {
                        panic("invalid content");
                    }
                }

                if ((nr_loops % TEST_LOOPS_PER_PRINT) == 0) {
                    printf("read ");
                }

                nr_loops++;
            }
        }

        rcu_read_leave();
    }
}

void
test_setup(void)
{
    struct thread_attr attr;
    struct thread *thread;
    struct cpumap *cpumap;
    int error;

    condition_init(&test_condition);
    mutex_init(&test_lock);

    error = cpumap_create(&cpumap);
    error_check(error, "cpumap_create");

    kmem_cache_init(&test_pdsc_cache, "test_pdsc",
                    sizeof(struct test_pdsc), 0, NULL, 0);

    thread_attr_init(&attr, THREAD_KERNEL_PREFIX "test_alloc");
    thread_attr_set_detached(&attr);
    cpumap_zero(cpumap);
    cpumap_set(cpumap, cpu_count() - 1);
    thread_attr_set_cpumap(&attr, cpumap);
    error = thread_create(&thread, &attr, test_alloc, NULL);
    error_check(error, "thread_create");

    thread_attr_init(&attr, THREAD_KERNEL_PREFIX "test_free");
    thread_attr_set_detached(&attr);
    cpumap_zero(cpumap);
    cpumap_set(cpumap, cpu_count() - 1);
    thread_attr_set_cpumap(&attr, cpumap);
    error = thread_create(&thread, &attr, test_free, NULL);
    error_check(error, "thread_create");

    thread_attr_init(&attr, THREAD_KERNEL_PREFIX "test_read");
    thread_attr_set_detached(&attr);
    cpumap_zero(cpumap);
    cpumap_set(cpumap, 0);
    thread_attr_set_cpumap(&attr, cpumap);
    error = thread_create(&thread, &attr, test_read, NULL);
    error_check(error, "thread_create");

    cpumap_destroy(cpumap);
}
