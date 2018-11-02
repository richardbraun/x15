/*
 * Copyright (c) 2018 Agustina Arzille.
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
 * This test checks that thread state transitions are correctly performed
 * when a thread is suspended and resumed. It does so by creating three
 * threads :
 *
 *  - The first thread spins on an atomic integer used as a lock, which
 *    puts it in the running state. The lock is released while the thread
 *    is suspended, and the thread is then resumed.
 *
 *  - The second thread waits on a zero-valued semaphore, which puts it
 *    in the sleeping state. The semaphore is signalled while the thread
 *    is suspended, and the thread is then resumed.
 *
 *  - The third suspends itself and is then resumed.
 *
 * As a result, the following transitions are tested :
 *  o CREATED -> RUNNING (*) -> SUSPENDED -> RUNNING
 *  o CREATED -> RUNNING -> SLEEPING (*) -> SUSPENDED -> RUNNING.
 *
 * (*) Step where a suspend request is made
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include <kern/atomic.h>
#include <kern/error.h>
#include <kern/init.h>
#include <kern/log.h>
#include <kern/panic.h>
#include <kern/semaphore.h>
#include <kern/thread.h>
#include <machine/cpu.h>
#include <test/test.h>

static void
test_wait_for_state(const struct thread *thread, unsigned int state)
{
    while (thread_state(thread) != state) {
        cpu_pause();
    }
}

static void
test_spin(void *arg)
{
    unsigned long *lock;

    lock = arg;

    while (atomic_cas(lock, 0UL, 1UL, ATOMIC_ACQ_REL) != 0) {
        cpu_pause();
    }
}

static void
test_sleep(void *arg)
{
    struct semaphore *sem;

    sem = arg;
    semaphore_wait(sem);
}

static void
test_suspend_self(void *arg)
{
    (void)arg;
    thread_suspend(thread_self());
}

static void
test_run(void *arg)
{
    struct thread *thread;
    struct thread_attr attr;
    unsigned long lock;
    struct semaphore sem;
    int error;

    (void)arg;

    lock = 1;
    thread_attr_init(&attr, "test_spin");
    error = thread_create(&thread, &attr, test_spin, &lock);
    error_check(error, "thread_create");

    test_wait_for_state(thread, THREAD_RUNNING);
    thread_suspend(thread);
    test_wait_for_state(thread, THREAD_SUSPENDED);

    atomic_store(&lock, 0, ATOMIC_RELEASE);
    thread_resume(thread);
    thread_join(thread);

    semaphore_init(&sem, 0);
    thread_attr_init(&attr, "test_sleep");
    error = thread_create(&thread, &attr, test_sleep, &sem);
    error_check(error, "thread_create");

    test_wait_for_state(thread, THREAD_SLEEPING);
    thread_suspend(thread);
    test_wait_for_state(thread, THREAD_SUSPENDED);
    thread_wakeup(thread);

    if (thread_state(thread) != THREAD_SUSPENDED) {
        panic("test: unexpected thread state");
    }

    semaphore_post(&sem);
    thread_resume(thread);
    thread_join(thread);

    thread_attr_init(&attr, "test_suspend_self");
    error = thread_create(&thread, &attr, test_suspend_self, NULL);
    test_wait_for_state(thread, THREAD_SUSPENDED);
    thread_resume(thread);
    thread_join(thread);

    log_info("done");
}

void __init
test_setup(void)
{
    struct thread_attr attr;
    int error;

    thread_attr_init(&attr, THREAD_KERNEL_PREFIX "test_run");
    thread_attr_set_detached(&attr);
    error = thread_create(NULL, &attr, test_run, NULL);
    error_check(error, "thread_create");
}
