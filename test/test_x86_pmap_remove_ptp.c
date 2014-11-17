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
 * This test module checks whether the TLB is correctly invalidated when
 * the structure of page table pages change. It is specifically tailored
 * for the x86 pmap module. It starts by allocating a physical page and
 * a region of virtual memory. This region is aligned so that creating
 * a physical mapping at its address involves the allocation of PTPs.
 * It then creates the physical mapping and writes the page, causing the
 * processor to cache page table entries. It then removes the physical
 * mapping. After that, it allocates one dummy physical page. The purpose
 * of this allocation is to force the pmap module to use pages at different
 * physical addresses when allocating new PTPs. Finally, it recreates the
 * same physical mapping as at the beginning, and attempts another write
 * access. If the TLB isn't correctly handled, the second physical mapping
 * creation fails because of stale entries when accessing intermediate PTPs.
 *
 * Note that, because of the complex optimizations around translation caching
 * in modern processors, this test may report false positives. So far, best
 * results are achieved with QEMU (without KVM), which seems to have reliable
 * behaviour.
 */

#include <kern/cpumap.h>
#include <kern/error.h>
#include <kern/panic.h>
#include <kern/param.h>
#include <kern/printk.h>
#include <kern/stddef.h>
#include <kern/string.h>
#include <kern/thread.h>
#include <machine/pmap.h>
#include <test/test.h>
#include <vm/vm_kmem.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>

static void
test_run(void *arg)
{
    struct vm_page *page, *dummy;
    unsigned long va;
    int error, flags;

    (void)arg;

    printk("creating mapping\n");
    page = vm_page_alloc(0, VM_PAGE_KMEM);

    if (page == NULL)
        panic("vm_page_alloc: %s", error_str(ERROR_NOMEM));

    va = 0;
    flags = VM_MAP_FLAGS(VM_PROT_ALL, VM_PROT_ALL, VM_INHERIT_NONE,
                         VM_ADV_DEFAULT, 0);
    error = vm_map_enter(kernel_map, &va, (1UL << 22), (1UL << 22), flags,
                         NULL, 0);
    error_check(error, "vm_map_enter");
    pmap_enter(kernel_pmap, va, vm_page_to_pa(page),
               VM_PROT_READ | VM_PROT_WRITE, PMAP_PEF_GLOBAL);
    pmap_update(kernel_pmap);

    printk("writing page, va:%p\n", (void *)va);
    memset((void *)va, 'a', PAGE_SIZE);

    printk("removing mapping\n");
    pmap_remove(kernel_pmap, va, cpumap_all());
    pmap_update(kernel_pmap);

    printk("allocating dummy physical page\n");
    dummy = vm_page_alloc(0, VM_PAGE_KMEM);

    if (dummy == NULL)
        panic("vm_page_alloc: %s", error_str(ERROR_NOMEM));

    printk("recreating mapping\n");
    pmap_enter(kernel_pmap, va, vm_page_to_pa(page),
               VM_PROT_READ | VM_PROT_WRITE, PMAP_PEF_GLOBAL);
    pmap_update(kernel_pmap);

    printk("rewriting page\n");
    memset((void *)va, 'a', PAGE_SIZE);

    printk("done\n");
}

void
test_setup(void)
{
    struct thread_attr attr;
    struct thread *thread;
    struct cpumap *cpumap;
    int error;

    /*
     * Bind to BSP and run at maximum priority to prevent anything else
     * from doing a complete TLB flush, meddling with the test.
     */

    error = cpumap_create(&cpumap);
    error_check(error, "cpumap_create");

    cpumap_zero(cpumap);
    cpumap_set(cpumap, 0);
    thread_attr_init(&attr, "x15_test_run");
    thread_attr_set_detached(&attr);
    thread_attr_set_cpumap(&attr, cpumap);
    thread_attr_set_policy(&attr, THREAD_SCHED_POLICY_FIFO);
    thread_attr_set_priority(&attr, THREAD_SCHED_RT_PRIO_MAX);
    error = thread_create(&thread, &attr, test_run, NULL);
    error_check(error, "thread_create");

    cpumap_destroy(cpumap);
}
