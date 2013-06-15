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

#include <vm/vm_anon.h>
#include <vm/vm_kmem.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>

#define OBJ_SIZE (PAGE_SIZE * 10)

static void
kernel_test(void *arg)
{
    struct vm_object *object;
    unsigned long addr;
    int error, flags;

    (void)arg;

    object = vm_anon_create(OBJ_SIZE);
    assert(object != NULL);
    addr = 0;
    flags = VM_MAP_PROT_ALL | VM_MAP_MAX_PROT_ALL | VM_MAP_INHERIT_NONE
            | VM_MAP_ADV_NORMAL;
    error = vm_map_enter(kernel_map, object, 0, &addr, OBJ_SIZE, 0, flags);
    assert(!error);
    printk("anonymous object mapped at %#lx\n", addr);
    vm_map_info(kernel_map);
    memset((void *)addr, '\0', OBJ_SIZE);
}

static void
start_test(void)
{
    struct thread_attr attr;
    struct thread *thread;
    int error;

    attr.name = "test";
    attr.cpumap = NULL;
    attr.task = NULL;
    attr.policy = THREAD_SCHED_POLICY_TS;
    attr.priority = THREAD_SCHED_TS_PRIO_DEFAULT;
    error = thread_create(&thread, &attr, kernel_test, NULL);
    assert(!error);
}

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

    start_test();

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
