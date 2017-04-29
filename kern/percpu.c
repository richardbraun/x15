/*
 * Copyright (c) 2014-2017 Richard Braun.
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

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <kern/assert.h>
#include <kern/error.h>
#include <kern/init.h>
#include <kern/macros.h>
#include <kern/panic.h>
#include <kern/param.h>
#include <kern/percpu.h>
#include <kern/printf.h>
#include <machine/cpu.h>
#include <vm/vm_kmem.h>
#include <vm/vm_page.h>

void *percpu_areas[X15_MAX_CPUS] __read_mostly;

static void *percpu_area_content __initdata;
static size_t percpu_area_size __initdata;
static int percpu_skip_warning __initdata;

void __init
percpu_bootstrap(void)
{
    percpu_areas[0] = &_percpu;
}

void __init
percpu_setup(void)
{
    struct vm_page *page;
    unsigned int order;

    percpu_area_size = &_percpu_end - &_percpu;
    printf("percpu: max_cpus: %u, section size: %zuk\n", X15_MAX_CPUS,
           percpu_area_size >> 10);
    assert(vm_page_aligned(percpu_area_size));

    if (percpu_area_size == 0) {
        return;
    }

    order = vm_page_order(percpu_area_size);
    page = vm_page_alloc(order, VM_PAGE_SEL_DIRECTMAP, VM_PAGE_KERNEL);

    if (page == NULL) {
        panic("percpu: unable to allocate memory for percpu area content");
    }

    percpu_area_content = vm_page_direct_ptr(page);
    memcpy(percpu_area_content, &_percpu, percpu_area_size);
}

int __init
percpu_add(unsigned int cpu)
{
    struct vm_page *page;
    unsigned int order;

    if (cpu >= ARRAY_SIZE(percpu_areas)) {
        if (!percpu_skip_warning) {
            printf("percpu: ignoring processor beyond id %zu\n",
                   ARRAY_SIZE(percpu_areas) - 1);
            percpu_skip_warning = 1;
        }

        return ERROR_INVAL;
    }

    if (percpu_areas[cpu] != NULL) {
        printf("percpu: error: id %u ignored, already registered\n", cpu);
        return ERROR_INVAL;
    }

    if (percpu_area_size == 0) {
        goto out;
    }

    order = vm_page_order(percpu_area_size);
    page = vm_page_alloc(order, VM_PAGE_SEL_DIRECTMAP, VM_PAGE_KERNEL);

    if (page == NULL) {
        printf("percpu: error: unable to allocate percpu area\n");
        return ERROR_NOMEM;
    }

    percpu_areas[cpu] = vm_page_direct_ptr(page);
    memcpy(percpu_area(cpu), percpu_area_content, percpu_area_size);

out:
    return 0;
}

void
percpu_cleanup(void)
{
    struct vm_page *page;
    uintptr_t va;

    va = (uintptr_t)percpu_area_content;
    page = vm_page_lookup(vm_page_direct_pa(va));
    vm_page_free(page, vm_page_order(percpu_area_size));
}
