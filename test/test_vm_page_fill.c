/*
 * Copyright (c) 2016-2017 Richard Braun.
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
 * The purpose of this test module is to show whether allocating and
 * modifying all available physical pages leads to unexpected problems.
 * In particular, if the early allocation code misbehaves, important
 * data structures such as kernel page tables may be considered free,
 * in which case this test will catch the error.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <kern/cpumap.h>
#include <kern/error.h>
#include <kern/list.h>
#include <kern/thread.h>
#include <machine/pmap.h>
#include <test/test.h>
#include <vm/vm_kmem.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>

static struct list test_pages;
static struct cpumap test_cpumap;

static unsigned char test_pattern = 1;

static void
test_write_pages(void)
{
    struct vm_page *page;
    int error, flags;
    uintptr_t va;

    for (;;) {
        page = vm_page_alloc(0, VM_PAGE_SEL_HIGHMEM, VM_PAGE_KERNEL);

        if (page == NULL) {
            break;
        }

        va = 0;
        flags = VM_MAP_FLAGS(VM_PROT_ALL, VM_PROT_ALL, VM_INHERIT_NONE,
                             VM_ADV_DEFAULT, 0);
        error = vm_map_enter(kernel_map, &va, PAGE_SIZE, 0, flags, NULL, 0);
        error_check(error, __func__);
        error = pmap_enter(kernel_pmap, va, vm_page_to_pa(page),
                           VM_PROT_READ | VM_PROT_WRITE, 0);
        error_check(error, __func__);
        error = pmap_update(kernel_pmap);
        error_check(error, __func__);
        memset((void *)va, test_pattern, PAGE_SIZE);
        error = pmap_remove(kernel_pmap, va, &test_cpumap);
        error_check(error, __func__);
        error = pmap_update(kernel_pmap);
        error_check(error, __func__);
        vm_map_remove(kernel_map, va, va + PAGE_SIZE);

        list_insert_tail(&test_pages, &page->node);
    }
}

static void
test_reset_pages(void)
{
    struct vm_page *page;
    int error, flags;
    uintptr_t va;

    while (!list_empty(&test_pages)) {
        page = list_first_entry(&test_pages, struct vm_page, node);
        list_remove(&page->node);

        va = 0;
        flags = VM_MAP_FLAGS(VM_PROT_ALL, VM_PROT_ALL, VM_INHERIT_NONE,
                             VM_ADV_DEFAULT, 0);
        error = vm_map_enter(kernel_map, &va, PAGE_SIZE, 0, flags, NULL, 0);
        error_check(error, __func__);
        error = pmap_enter(kernel_pmap, va, vm_page_to_pa(page),
                           VM_PROT_READ | VM_PROT_WRITE, 0);
        error_check(error, __func__);
        error = pmap_update(kernel_pmap);
        error_check(error, __func__);
        memset((void *)va, 0, PAGE_SIZE);
        error = pmap_remove(kernel_pmap, va, &test_cpumap);
        error_check(error, __func__);
        error = pmap_update(kernel_pmap);
        error_check(error, __func__);
        vm_map_remove(kernel_map, va, va + PAGE_SIZE);

        vm_page_free(page, 0);
    }
}

static void
test_run(void *arg)
{
    unsigned int i;

    (void)arg;

    for (i = 0; /* no condition */; i++) {
        printf("test: pass:%u pattern:%hhx\n", i, test_pattern);
        test_write_pages();
        test_reset_pages();
        test_pattern++;
    }
}

void
test_setup(void)
{
    struct thread_attr attr;
    struct thread *thread;
    int error;

    list_init(&test_pages);
    cpumap_zero(&test_cpumap);
    cpumap_set(&test_cpumap, cpu_id());

    thread_attr_init(&attr, THREAD_KERNEL_PREFIX "test_run");
    thread_attr_set_detached(&attr);
    thread_attr_set_cpumap(&attr, &test_cpumap);
    error = thread_create(&thread, &attr, test_run, NULL);
    error_check(error, "thread_create");
}
