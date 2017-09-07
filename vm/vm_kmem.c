/*
 * Copyright (c) 2011-2017 Richard Braun.
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

#include <kern/cpumap.h>
#include <kern/init.h>
#include <kern/macros.h>
#include <machine/page.h>
#include <machine/pmap.h>
#include <machine/types.h>
#include <vm/vm_adv.h>
#include <vm/vm_inherit.h>
#include <vm/vm_kmem.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_prot.h>

static uint64_t
vm_kmem_offset(uintptr_t va)
{
    assert(va >= PMAP_START_KMEM_ADDRESS);
    return va - PMAP_START_KMEM_ADDRESS;
}

static int __init
vm_kmem_setup(void)
{
    uint64_t size;

    size = vm_kmem_offset(PMAP_END_KMEM_ADDRESS);
    vm_object_init(vm_object_get_kernel_object(), size);
    return 0;
}

INIT_OP_DEFINE(vm_kmem_setup,
               INIT_OP_DEP(pmap_bootstrap, true),
               INIT_OP_DEP(vm_map_bootstrap, true),
               INIT_OP_DEP(vm_object_setup, true),
               INIT_OP_DEP(vm_page_setup, true));

__unused static int
vm_kmem_alloc_check(size_t size)
{
    if (!vm_page_aligned(size)
        || (size == 0)) {
        return -1;
    }

    return 0;
}

__unused static int
vm_kmem_free_check(uintptr_t va, size_t size)
{
    if (!vm_page_aligned(va)) {
        return -1;
    }

    return vm_kmem_alloc_check(size);
}

void *
vm_kmem_alloc_va(size_t size)
{
    int error, flags;
    uintptr_t va;

    assert(vm_kmem_alloc_check(size) == 0);

    va = 0;
    flags = VM_MAP_FLAGS(VM_PROT_ALL, VM_PROT_ALL, VM_INHERIT_NONE,
                         VM_ADV_DEFAULT, 0);
    error = vm_map_enter(vm_map_get_kernel_map(), &va, size, 0, flags, NULL, 0);

    if (error) {
        return NULL;
    }

    return (void *)va;
}

void
vm_kmem_free_va(void *addr, size_t size)
{
    uintptr_t va;

    va = (uintptr_t)addr;
    assert(vm_kmem_free_check(va, size) == 0);
    vm_map_remove(vm_map_get_kernel_map(), va, va + vm_page_round(size));
}

void *
vm_kmem_alloc(size_t size)
{
    struct vm_object *kernel_object;
    struct pmap *kernel_pmap;
    struct vm_page *page;
    uintptr_t va, start, end;
    int error;

    size = vm_page_round(size);
    va = (uintptr_t)vm_kmem_alloc_va(size);

    if (va == 0) {
        return NULL;
    }

    kernel_object = vm_object_get_kernel_object();
    kernel_pmap = pmap_get_kernel_pmap();

    for (start = va, end = va + size; start < end; start += PAGE_SIZE) {
        page = vm_page_alloc(0, VM_PAGE_SEL_HIGHMEM, VM_PAGE_KERNEL);

        if (page == NULL) {
            goto error;
        }

        /*
         * The page becomes managed by the object and is freed in case
         * of failure.
         */
        error = vm_object_insert(kernel_object, page, vm_kmem_offset(start));

        if (error) {
            goto error;
        }

        error = pmap_enter(kernel_pmap, start, vm_page_to_pa(page),
                           VM_PROT_READ | VM_PROT_WRITE, PMAP_PEF_GLOBAL);

        if (error || (start - va == vm_page_ptob(1000))) {
            goto error;
        }
    }

    error = pmap_update(kernel_pmap);

    if (error) {
        goto error;
    }

    return (void *)va;

error:
    vm_kmem_free((void *)va, size);
    return NULL;
}

void
vm_kmem_free(void *addr, size_t size)
{
    const struct cpumap *cpumap;
    struct pmap *kernel_pmap;
    uintptr_t va, end;

    va = (uintptr_t)addr;
    size = vm_page_round(size);
    end = va + size;
    cpumap = cpumap_all();
    kernel_pmap = pmap_get_kernel_pmap();

    while (va < end) {
        pmap_remove(kernel_pmap, va, cpumap);
        va += PAGE_SIZE;
    }

    pmap_update(kernel_pmap);
    vm_object_remove(vm_object_get_kernel_object(),
                     vm_kmem_offset((uintptr_t)addr),
                     vm_kmem_offset(end));
    vm_kmem_free_va(addr, size);
}

void *
vm_kmem_map_pa(phys_addr_t pa, size_t size,
               uintptr_t *map_vap, size_t *map_sizep)
{
    struct pmap *kernel_pmap;
    uintptr_t offset, map_va;
    size_t map_size;
    phys_addr_t start;
    int error;

    kernel_pmap = pmap_get_kernel_pmap();

    start = vm_page_trunc(pa);
    map_size = vm_page_round(pa + size) - start;
    map_va = (uintptr_t)vm_kmem_alloc_va(map_size);

    if (map_va == 0) {
        return NULL;
    }

    for (offset = 0; offset < map_size; offset += PAGE_SIZE) {
        error = pmap_enter(kernel_pmap, map_va + offset, start + offset,
                           VM_PROT_READ | VM_PROT_WRITE, PMAP_PEF_GLOBAL);

        if (error) {
            goto error;
        }
    }

    error = pmap_update(kernel_pmap);

    if (error) {
        goto error;
    }

    if (map_vap != NULL) {
        *map_vap = map_va;
    }

    if (map_sizep != NULL) {
        *map_sizep = map_size;
    }

    return (void *)(map_va + (uintptr_t)(pa & PAGE_MASK));

error:
    vm_kmem_unmap_pa(map_va, map_size);
    return NULL;
}

void
vm_kmem_unmap_pa(uintptr_t map_va, size_t map_size)
{
    const struct cpumap *cpumap;
    struct pmap *kernel_pmap;
    uintptr_t va, end;

    cpumap = cpumap_all();
    kernel_pmap = pmap_get_kernel_pmap();
    end = map_va + map_size;

    for (va = map_va; va < end; va += PAGE_SIZE) {
        pmap_remove(kernel_pmap, va, cpumap);
    }

    pmap_update(kernel_pmap);
    vm_kmem_free_va((void *)map_va, map_size);
}
