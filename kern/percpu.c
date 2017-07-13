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

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <kern/error.h>
#include <kern/init.h>
#include <kern/log.h>
#include <kern/macros.h>
#include <kern/panic.h>
#include <kern/percpu.h>
#include <machine/cpu.h>
#include <vm/vm_kmem.h>
#include <vm/vm_page.h>

void *percpu_areas[X15_MAX_CPUS] __read_mostly;

static void *percpu_area_content __initdata;
static size_t percpu_area_size __initdata;
static int percpu_skip_warning __initdata;

static int __init
percpu_bootstrap(void)
{
    percpu_areas[0] = &_percpu;
    return 0;
}

INIT_OP_DEFINE(percpu_bootstrap);

static int __init
percpu_setup(void)
{
    struct vm_page *page;
    unsigned int order;

    percpu_area_size = &_percpu_end - &_percpu;
    log_info("percpu: max_cpus: %u, section size: %zuk", X15_MAX_CPUS,
             percpu_area_size >> 10);
    assert(vm_page_aligned(percpu_area_size));

    if (percpu_area_size == 0) {
        return 0;
    }

    order = vm_page_order(percpu_area_size);
    page = vm_page_alloc(order, VM_PAGE_SEL_DIRECTMAP, VM_PAGE_KERNEL);

    if (page == NULL) {
        panic("percpu: unable to allocate memory for percpu area content");
    }

    percpu_area_content = vm_page_direct_ptr(page);
    memcpy(percpu_area_content, &_percpu, percpu_area_size);
    return 0;
}

INIT_OP_DEFINE(percpu_setup,
               INIT_OP_DEP(percpu_bootstrap, true),
               INIT_OP_DEP(vm_page_setup, true));

int __init
percpu_add(unsigned int cpu)
{
    struct vm_page *page;
    unsigned int order;

    if (cpu >= ARRAY_SIZE(percpu_areas)) {
        if (!percpu_skip_warning) {
            log_warning("percpu: ignoring processor beyond id %zu",
                        ARRAY_SIZE(percpu_areas) - 1);
            percpu_skip_warning = 1;
        }

        return ERROR_INVAL;
    }

    if (percpu_areas[cpu] != NULL) {
        log_err("percpu: id %u ignored, already registered", cpu);
        return ERROR_INVAL;
    }

    if (percpu_area_size == 0) {
        goto out;
    }

    order = vm_page_order(percpu_area_size);
    page = vm_page_alloc(order, VM_PAGE_SEL_DIRECTMAP, VM_PAGE_KERNEL);

    if (page == NULL) {
        log_err("percpu: unable to allocate percpu area");
        return ERROR_NOMEM;
    }

    percpu_areas[cpu] = vm_page_direct_ptr(page);
    memcpy(percpu_area(cpu), percpu_area_content, percpu_area_size);

out:
    return 0;
}

static int __init
percpu_cleanup(void)
{
    struct vm_page *page;
    uintptr_t va;

    va = (uintptr_t)percpu_area_content;
    page = vm_page_lookup(vm_page_direct_pa(va));
    vm_page_free(page, vm_page_order(percpu_area_size));
    return 0;
}

INIT_OP_DEFINE(percpu_cleanup,
               INIT_OP_DEP(cpu_mp_probe, true),
               INIT_OP_DEP(percpu_setup, true),
               INIT_OP_DEP(vm_page_setup, true));
