/*
 * Copyright (c) 2017 Richard Braun.
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
 * This test module is a stress test, expected to never terminate, of
 * priority inheritance with mutexes. It creates a priority inheritance
 * tree by starting multiple threads manipulating multiple mutexes.
 *
 * Here is one intended state of the priority inheritance tree :
 *
 *
 *            C->M2-+
 *                  |
 *         D--+     +->B->M1->A
 *            |     |
 *            +->M3-+
 *            |
 *         E--+
 *
 *
 * M1,M2,M3,etc... are mutexes and A,B,C,etc... are threads. The thread
 * priorities p(thread) are ordered such that p(A) < p(B) < p(C) etc...
 * An arrow from a mutex to a thread indicates ownership, such that
 * M1->A means that A owns M1. An arrow from a thread to a mutex indicates
 * waiting, such that B->M1 means that B is waiting for M1 to be unlocked.
 *
 * In addition, thread B is actually many threads, each terminating after
 * unlocking their mutexes. Also, the priority of thread C is regularly
 * increased to p(E) + 1 and later restored to p(C).
 *
 * Here is the list of all the cases this test must cover :
 *  - Priority inheritance: All threads can get their real priority boosted.
 *    C can be boosted if it owns M2 and B waits for it while inheriting
 *    from E, and E can be boosted when p(C) is temporarily increased.
 *  - Return to normal priority: after releasing all locks, a thread must
 *    have reset its real priority to its user priority.
 *  - Priority changes: When the priority of C is increased, that priority
 *    must take precedence over all others.
 *  - Thread destruction resilience: Check that priority propagation never
 *    accesses a destroyed thread.
 *
 * Note that this test doesn't check that priority propagation correctly
 * adjusts the top priority after lowering the priority of thread C back
 * to p(C).
 *
 * In order to artificially create priority inversions, all threads run on
 * separate processors, making this test require 5 processors.
 *
 * TODO Use timers instead of busy-waiting so that binding to processors
 * isn't required.
 *
 * The test should output a couple of messages about thread priorities
 * being boosted, and then frequent updates from each thread to show
 * they're all making progress. Thread B suffers from contention the most
 * so its report frequency should be lower. Thread A suffers from contention
 * the least and should be the most frequent to report progress. Because of
 * contention from B, D and E on M3, D rarely gets boosted. The reason is
 * that, when B owns the mutex, E is likely to wait on M3 soon enough that
 * it will be awaken before D, preventing the conditions for priority
 * inheritance to occur.
 *
 * Note that the test uses regular mutexes instead of real-time mutexes,
 * so that its behaviour can be analyzed for both types depending on
 * build options.
 */

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <kern/cpumap.h>
#include <kern/error.h>
#include <kern/mutex.h>
#include <kern/panic.h>
#include <kern/syscnt.h>
#include <kern/thread.h>
#include <kern/turnstile.h>
#include <test/test.h>

#define TEST_PRIO_A (THREAD_SCHED_RT_PRIO_MIN + 1)
#define TEST_PRIO_B (TEST_PRIO_A + 1)
#define TEST_PRIO_C (TEST_PRIO_B + 1)
#define TEST_PRIO_D (TEST_PRIO_C + 1)
#define TEST_PRIO_E (TEST_PRIO_D + 1)

#define TEST_NR_LOCK_LOOPS          500
#define TEST_NR_CONSUME_CPU_LOOPS   10000000

static struct mutex test_mutex_1;
static struct mutex test_mutex_2;
static struct mutex test_mutex_3;

static const char *
test_thread_from_priority(unsigned short priority)
{
    switch (priority) {
    case TEST_PRIO_A:
        return "a";
    case TEST_PRIO_B:
        return "b";
    case TEST_PRIO_C:
        return "c";
    case TEST_PRIO_D:
        return "d";
    case TEST_PRIO_E:
        return "e";
    case TEST_PRIO_E + 1:
        return "e+";
    default:
        panic("invalid priority %u", priority);
    }
}

static char
test_get_name(void)
{
    const char *name;
    size_t length;

    name = thread_self()->name;
    length = strlen(name);
    return name[length - 1];
}

static void
test_consume_cpu(void)
{
    volatile unsigned int i;

    for (i = 0; i < TEST_NR_CONSUME_CPU_LOOPS; i++);
}

static void
test_check_initial_priority(void)
{
    unsigned short user_priority, real_priority;
    struct thread *thread;

    thread = thread_self();
    user_priority = thread_user_priority(thread);
    real_priority = thread_real_priority(thread);

    if (user_priority != real_priority) {
        panic("%c: invalid initial priority %hu",
              test_get_name(), real_priority);
    }
}

static void
test_for_priority_boosted(unsigned short *highest_priority)
{
    unsigned short user_priority, real_priority;
    struct turnstile_td *td;
    struct thread *thread;

    thread = thread_self();
    td = thread_turnstile_td(thread);

    turnstile_td_lock(td);

    user_priority = thread_user_priority(thread);
    real_priority = thread_real_priority(thread);

    if (user_priority != real_priority) {
        if (user_priority > real_priority) {
            panic("%c: invalid real priority: %hu (boosted:%u)",
                  test_get_name(), real_priority, thread->boosted);
        }

        if (real_priority > *highest_priority) {
            printf("%c: real priority boosted to %s\n",
                   test_get_name(), test_thread_from_priority(real_priority));
            *highest_priority = real_priority;
        }
    }

    turnstile_td_unlock(td);
}

static void
test_for_priority_deboosted(void)
{
    unsigned short user_priority, real_priority;
    struct turnstile_td *td;
    struct thread *thread;

    thread = thread_self();
    td = thread_turnstile_td(thread);

    turnstile_td_lock(td);

    user_priority = thread_user_priority(thread);
    real_priority = thread_real_priority(thread);

    if (user_priority != real_priority) {
        panic("%c: real priority not reset (boosted:%d)", test_get_name(), thread->boosted);
    }

    turnstile_td_unlock(td);
}

static void
test_report_progress(unsigned int i)
{
    printf("%c:%u ", test_get_name(), i);
}

static void
test_a(void *arg)
{
    unsigned short highest_priority;
    unsigned int i, j;

    (void)arg;

    test_check_initial_priority();

    highest_priority = 0;

    for (i = 1; /* no condition */; i++) {
        for (j = 0; j < TEST_NR_LOCK_LOOPS; j++) {
            mutex_lock(&test_mutex_1);
            test_consume_cpu();
            test_for_priority_boosted(&highest_priority);
            mutex_unlock(&test_mutex_1);

            test_for_priority_deboosted();

            test_consume_cpu();
        }

        test_report_progress(i);
    }
}

static void
test_b(void *arg)
{
    test_check_initial_priority();

    mutex_lock(&test_mutex_3);
    mutex_lock(&test_mutex_2);
    mutex_lock(&test_mutex_1);
    test_consume_cpu();
    test_for_priority_boosted(arg);
    mutex_unlock(&test_mutex_1);
    test_consume_cpu();
    mutex_unlock(&test_mutex_2);
    test_consume_cpu();
    mutex_unlock(&test_mutex_3);

    /*
     * It would be better if the thread could immediately terminate, but
     * it's also the thread that locks multiple mutexes, so make sure it
     * was correctly deboosted. This should be cheap enough to not matter
     * much.
     */
    test_for_priority_deboosted();
}

static void
test_manage_b(void *arg)
{
    unsigned short highest_priority;
    struct thread_attr attr;
    struct thread *thread_b;
    struct cpumap *cpumap;
    unsigned int i, j;
    int error;

    (void)arg;

    error = cpumap_create(&cpumap);
    error_check(error, "cpumap_create");
    cpumap_zero(cpumap);
    cpumap_set(cpumap, 1);
    thread_attr_init(&attr, THREAD_KERNEL_PREFIX "test_b");
    thread_attr_set_policy(&attr, THREAD_SCHED_POLICY_FIFO);
    thread_attr_set_priority(&attr, TEST_PRIO_B);
    thread_attr_set_cpumap(&attr, cpumap);
    cpumap_destroy(cpumap);

    highest_priority = 0;

    for (i = 1; /* no condition */; i++) {
        for (j = 0; j < TEST_NR_LOCK_LOOPS; j++) {
            error = thread_create(&thread_b, &attr, test_b, &highest_priority);
            error_check(error, "thread_create");
            thread_join(thread_b);

            test_consume_cpu();
        }

        printf("b:%u ", i);
        syscnt_info("thread_boosts");
    }
}

static void
test_c(void *arg)
{
    unsigned short highest_priority;
    unsigned int i, j;

    (void)arg;

    test_check_initial_priority();

    highest_priority = 0;

    for (i = 1; /* no condition */; i++) {
        for (j = 0; j < TEST_NR_LOCK_LOOPS; j++) {
            mutex_lock(&test_mutex_2);
            test_consume_cpu();
            test_for_priority_boosted(&highest_priority);
            mutex_unlock(&test_mutex_2);

            test_for_priority_deboosted();

            test_consume_cpu();
        }

        test_report_progress(i);
    }
}

static void
test_chprio_c(void *arg)
{
    struct thread *thread_c;

    thread_c = arg;

    test_consume_cpu();

    for (;;) {
        thread_setscheduler(thread_c, THREAD_SCHED_POLICY_FIFO,
                            TEST_PRIO_E + 1);
        thread_setscheduler(thread_c, THREAD_SCHED_POLICY_FIFO,
                            TEST_PRIO_C);
    }
}

static void
test_d(void *arg)
{
    unsigned short highest_priority;
    unsigned int i, j;

    (void)arg;

    test_check_initial_priority();

    highest_priority = 0;

    for (i = 1; /* no condition */; i++) {
        for (j = 0; j < TEST_NR_LOCK_LOOPS; j++) {
            mutex_lock(&test_mutex_3);
            test_consume_cpu();
            test_for_priority_boosted(&highest_priority);
            mutex_unlock(&test_mutex_3);

            test_for_priority_deboosted();

            test_consume_cpu();
        }

        test_report_progress(i);
    }
}

static void
test_e(void *arg)
{
    unsigned short highest_priority;
    unsigned int i, j;

    (void)arg;

    test_check_initial_priority();

    highest_priority = 0;

    for (i = 1; /* no condition */; i++) {
        for (j = 0; j < TEST_NR_LOCK_LOOPS; j++) {
            mutex_lock(&test_mutex_3);
            test_consume_cpu();
            test_for_priority_boosted(&highest_priority);
            mutex_unlock(&test_mutex_3);

            test_for_priority_deboosted();

            test_consume_cpu();
        }

        test_report_progress(i);
    }
}

void
test_setup(void)
{
    struct thread_attr attr;
    struct thread *thread;
    struct cpumap *cpumap;
    int error;

    mutex_init(&test_mutex_1);
    mutex_init(&test_mutex_2);
    mutex_init(&test_mutex_3);

    error = cpumap_create(&cpumap);
    error_check(error, "cpumap_create");

    cpumap_zero(cpumap);
    cpumap_set(cpumap, 0);
    thread_attr_init(&attr, THREAD_KERNEL_PREFIX "test_a");
    thread_attr_set_detached(&attr);
    thread_attr_set_policy(&attr, THREAD_SCHED_POLICY_FIFO);
    thread_attr_set_priority(&attr, TEST_PRIO_A);
    thread_attr_set_cpumap(&attr, cpumap);
    error = thread_create(&thread, &attr, test_a, NULL);
    error_check(error, "thread_create");

    cpumap_zero(cpumap);
    cpumap_set(cpumap, 1);
    thread_attr_init(&attr, THREAD_KERNEL_PREFIX "test_manage_b");
    thread_attr_set_detached(&attr);
    thread_attr_set_policy(&attr, THREAD_SCHED_POLICY_FIFO);
    thread_attr_set_priority(&attr, TEST_PRIO_B);
    thread_attr_set_cpumap(&attr, cpumap);
    error = thread_create(&thread, &attr, test_manage_b, NULL);
    error_check(error, "thread_create");

    cpumap_zero(cpumap);
    cpumap_set(cpumap, 2);
    thread_attr_init(&attr, THREAD_KERNEL_PREFIX "test_c");
    thread_attr_set_detached(&attr);
    thread_attr_set_policy(&attr, THREAD_SCHED_POLICY_FIFO);
    thread_attr_set_priority(&attr, TEST_PRIO_C);
    thread_attr_set_cpumap(&attr, cpumap);
    error = thread_create(&thread, &attr, test_c, NULL);
    error_check(error, "thread_create");

    thread_attr_init(&attr, THREAD_KERNEL_PREFIX "test_chprio_c");
    thread_attr_set_detached(&attr);
    error = thread_create(&thread, &attr, test_chprio_c, thread);
    error_check(error, "thread_create");

    cpumap_zero(cpumap);
    cpumap_set(cpumap, 3);
    thread_attr_init(&attr, THREAD_KERNEL_PREFIX "test_d");
    thread_attr_set_detached(&attr);
    thread_attr_set_policy(&attr, THREAD_SCHED_POLICY_FIFO);
    thread_attr_set_priority(&attr, TEST_PRIO_D);
    thread_attr_set_cpumap(&attr, cpumap);
    error = thread_create(&thread, &attr, test_d, NULL);
    error_check(error, "thread_create");

    cpumap_zero(cpumap);
    cpumap_set(cpumap, 4);
    thread_attr_init(&attr, THREAD_KERNEL_PREFIX "test_e");
    thread_attr_set_detached(&attr);
    thread_attr_set_policy(&attr, THREAD_SCHED_POLICY_FIFO);
    thread_attr_set_priority(&attr, TEST_PRIO_E);
    thread_attr_set_cpumap(&attr, cpumap);
    error = thread_create(&thread, &attr, test_e, NULL);
    error_check(error, "thread_create");

    cpumap_destroy(cpumap);
}
