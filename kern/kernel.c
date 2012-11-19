/*
 * Copyright (c) 2011, 2012 Richard Braun.
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
 */

#include <kern/init.h>
#include <kern/kernel.h>
#include <kern/panic.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <machine/cpu.h>

static void __init
kernel_setup(void *arg)
{
    (void)arg;

    for (;;)
        cpu_idle();
}

void __init
kernel_main(void)
{
    struct thread *thread;
    int error;

    task_setup();
    thread_setup();
    cpu_mp_setup();

    error = thread_create(&thread, "core", kernel_task, kernel_setup, NULL);

    if (error)
        panic("kernel: unable to create kernel thread");

    thread_run();

    /* Never reached */
}
