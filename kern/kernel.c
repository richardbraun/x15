/*
 * Copyright (c) 2011, 2012, 2013 Richard Braun.
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

#include <kern/cpumap.h>
#include <kern/init.h>
#include <kern/kernel.h>
#include <kern/llsync.h>
#include <kern/panic.h>
#include <kern/rdxtree.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/work.h>
#include <machine/cpu.h>

void __init
kernel_main(void)
{
    assert(!cpu_intr_enabled());

    /* Enable interrupts to allow inter-processor pmap updates */
    cpu_intr_enable();

    /* Initialize the kernel */
    rdxtree_setup();
    cpumap_setup();
    task_setup();
    thread_setup();
    work_setup();
    llsync_setup();

    /* Rendezvous with APs */
    cpu_mp_sync();

    /* Run the scheduler */
    thread_run();

    /* Never reached */
}

void __init
kernel_ap_main(void)
{
    assert(!cpu_intr_enabled());

    /*
     * Enable interrupts to allow inter-processor pmap updates while the BSP
     * is initializing the kernel.
     */
    cpu_intr_enable();

    /* Wait for the BSP to complete kernel initialization */
    cpu_ap_sync();

    /* Run the scheduler */
    thread_run();

    /* Never reached */
}
