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

#include <vm/vm_adv.h>
#include <vm/vm_anon.h>
#include <vm/vm_inherit.h>
#include <vm/vm_kmem.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_prot.h>

#define OBJ_SIZE (PAGE_SIZE * 4)

static void
kernel_test_fault(void *arg)
{
    struct vm_object *object;
    struct vm_map *map;
    unsigned long addr;
    int error, flags;

    (void)arg;

    map = thread_self()->task->map;

    object = vm_anon_create(OBJ_SIZE);
    assert(object != NULL);
    addr = 0;
    flags = VM_MAP_FLAGS(VM_PROT_ALL, VM_PROT_ALL, VM_INHERIT_DEFAULT,
                         VM_ADV_DEFAULT, 0);
    error = vm_map_enter(map, object, 0, &addr, OBJ_SIZE, 0, flags);
    assert(!error);
    printk("anonymous object mapped at %#lx\n", addr);
    vm_map_info(map);
    printk("filling object\n");
    memset((void *)addr, 0xff, OBJ_SIZE);
    printk("object filled\n");
    printk("removing physical mappings\n");

    /* TODO pmap_remove() */
    pmap_kremove(addr, addr + OBJ_SIZE);
    pmap_update(kernel_pmap, addr, addr + OBJ_SIZE);

    printk("filling object again\n");
    memset((void *)addr, 0xff, OBJ_SIZE);
    printk("object filled\n");
}

static void
start_test(void)
{
    struct thread_attr attr;
    struct thread *thread;
    struct task *task;
    int error;

    error = task_create(&task, "test_fault");
    assert(!error);

    attr.name = "test_fault";
    attr.cpumap = NULL;
    attr.task = task;
    attr.policy = THREAD_SCHED_POLICY_TS;
    attr.priority = THREAD_SCHED_TS_PRIO_DEFAULT;
    error = thread_create(&thread, &attr, kernel_test_fault, NULL);
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
