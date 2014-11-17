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
 */

#include <kern/assert.h>
#include <kern/error.h>
#include <kern/init.h>
#include <kern/macros.h>
#include <kern/panic.h>
#include <kern/param.h>
#include <kern/percpu.h>
#include <kern/printk.h>
#include <kern/stddef.h>
#include <kern/string.h>
#include <machine/cpu.h>
#include <vm/vm_kmem.h>
#include <vm/vm_page.h>

void *percpu_areas[MAX_CPUS] __read_mostly;

static void *percpu_area_content __initdata;
static size_t percpu_size __initdata;
static int percpu_skip_warning __initdata;

void __init
percpu_bootstrap(void)
{
    percpu_areas[0] = &_percpu;
    percpu_size = &_epercpu - &_percpu;
}

void __init
percpu_setup(void)
{
    printk("percpu: max_cpus: %u, section size: %zuk\n",
           MAX_CPUS, percpu_size >> 10);
    assert(vm_page_aligned(percpu_size));

    if (percpu_size == 0)
        return;

    percpu_area_content = vm_kmem_alloc(percpu_size);

    if (percpu_area_content == NULL)
        panic("percpu: unable to allocate memory for percpu area content");

    memcpy(percpu_area_content, &_percpu, percpu_size);
}

int __init
percpu_add(unsigned int cpu)
{
    if (cpu >= ARRAY_SIZE(percpu_areas)) {
        if (!percpu_skip_warning) {
            printk("percpu: ignoring processor beyond id %zu\n",
                   ARRAY_SIZE(percpu_areas) - 1);
            percpu_skip_warning = 1;
        }

        return ERROR_INVAL;
    }

    if (percpu_areas[cpu] != NULL) {
        printk("percpu: error: id %u ignored, already registered\n", cpu);
        return ERROR_INVAL;
    }

    if (percpu_size == 0)
        goto out;

    percpu_areas[cpu] = vm_kmem_alloc(percpu_size);

    if (percpu_areas[cpu] == NULL) {
        printk("percpu: error: unable to allocate percpu area\n");
        return ERROR_NOMEM;
    }

    memcpy(percpu_area(cpu), percpu_area_content, percpu_size);

out:
    return 0;
}

void
percpu_cleanup(void)
{
    vm_kmem_free(percpu_area_content, percpu_size);
}
