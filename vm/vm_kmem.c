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

#include <kern/assert.h>
#include <kern/init.h>
#include <kern/panic.h>
#include <kern/param.h>
#include <kern/stddef.h>
#include <kern/types.h>
#include <machine/pmap.h>
#include <vm/vm_adv.h>
#include <vm/vm_inherit.h>
#include <vm/vm_kmem.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>
#include <vm/vm_phys.h>
#include <vm/vm_prot.h>

/*
 * Kernel map and storage.
 */
static struct vm_map kernel_map_store;
struct vm_map *kernel_map = &kernel_map_store;

/*
 * Heap boundaries during bootstrap.
 */
static unsigned long vm_kmem_boot_start __initdata;
static unsigned long vm_kmem_boot_end __initdata;

void __init
vm_kmem_setup(void)
{
    vm_kmem_boot_start = VM_MIN_KERNEL_ADDRESS;
    vm_kmem_boot_end = VM_MAX_KERNEL_ADDRESS;
}

unsigned long __init
vm_kmem_bootalloc(size_t size)
{
    unsigned long start, va;
    phys_addr_t pa;

    assert(size > 0);

    size = vm_page_round(size);

    if ((vm_kmem_boot_end - vm_kmem_boot_start) < size)
        panic("vm_kmem: no virtual space available");

    start = vm_kmem_boot_start;
    vm_kmem_boot_start += size;

    if (pmap_klimit() < vm_kmem_boot_start)
        pmap_kgrow(vm_kmem_boot_start);

    for (va = start; va < vm_kmem_boot_start; va += PAGE_SIZE) {
        pa = vm_phys_bootalloc();
        pmap_kenter(va, pa, VM_PROT_READ | VM_PROT_WRITE);
    }

    pmap_update(kernel_pmap, start, vm_kmem_boot_start);
    return start;
}

void __init
vm_kmem_boot_space(unsigned long *start, unsigned long *end)
{
    *start = VM_MIN_KERNEL_ADDRESS;
    *end = vm_kmem_boot_start;
}

struct vm_page *
vm_kmem_lookup_page(unsigned long va)
{
    phys_addr_t pa;

    pa = pmap_extract(kernel_pmap, va);

    if (pa == 0)
        return NULL;

    return vm_phys_lookup_page(pa);
}

static int
vm_kmem_alloc_check(size_t size)
{
    if (size == 0)
        return -1;

    return 0;
}

static int
vm_kmem_free_check(unsigned long addr, size_t size)
{
    if (!vm_page_aligned(addr))
        return -1;

    return vm_kmem_alloc_check(size);
}

unsigned long
vm_kmem_alloc_va(size_t size)
{
    unsigned long va;
    int error, flags;

    assert(vm_kmem_alloc_check(size) == 0);

    size = vm_page_round(size);

    va = 0;
    flags = VM_MAP_FLAGS(VM_PROT_ALL, VM_PROT_ALL, VM_INHERIT_NONE,
                         VM_ADV_DEFAULT, 0);
    error = vm_map_enter(kernel_map, NULL, 0, &va, size, 0, flags);

    if (error)
        return 0;

    return va;
}

void
vm_kmem_free_va(unsigned long addr, size_t size)
{
    unsigned long end;

    assert(vm_kmem_free_check(addr, size) == 0);

    end = addr + vm_page_round(size);
    pmap_kremove(addr, end);
    pmap_update(kernel_pmap, addr, end);
    vm_map_remove(kernel_map, addr, end);
}

unsigned long
vm_kmem_alloc(size_t size)
{
    struct vm_page *page;
    unsigned long va, start, end;

    va = vm_kmem_alloc_va(size);

    if (va == 0)
        return 0;

    for (start = va, end = va + size; start < end; start += PAGE_SIZE) {
        page = vm_phys_alloc(0);

        if (page == NULL)
            goto error_page;

        pmap_kenter(start, vm_page_to_pa(page), VM_PROT_READ | VM_PROT_WRITE);
    }

    pmap_update(kernel_pmap, va, end);
    return va;

error_page:
    vm_kmem_free(va, size);
    return 0;
}

void
vm_kmem_free(unsigned long addr, size_t size)
{
    struct vm_page *page;
    unsigned long va, end;
    phys_addr_t pa;

    size = vm_page_round(size);
    end = addr + size;

    for (va = addr; va < end; va += PAGE_SIZE) {
        pa = pmap_extract(kernel_pmap, va);

        if (pa == 0)
            continue;

        page = vm_phys_lookup_page(pa);
        assert(page != NULL);
        vm_phys_free(page, 0);
    }

    vm_kmem_free_va(addr, size);
}

void *
vm_kmem_map_pa(phys_addr_t addr, size_t size, unsigned long *map_addrp,
               size_t *map_sizep)
{
    unsigned long offset, map_addr;
    size_t map_size;
    phys_addr_t start;

    start = vm_page_trunc(addr);
    map_size = vm_page_round(addr + size) - start;
    map_addr = vm_kmem_alloc_va(map_size);

    if (map_addr == 0)
        return NULL;

    for (offset = 0; offset < map_size; offset += PAGE_SIZE)
        pmap_kenter(map_addr + offset, start + offset,
                    VM_PROT_READ | VM_PROT_WRITE);

    pmap_update(kernel_pmap, map_addr, map_addr + map_size);

    if (map_addrp != NULL)
        *map_addrp = map_addr;

    if (map_sizep != NULL)
        *map_sizep = map_size;

    return (void *)(map_addr + (unsigned long)(addr & PAGE_MASK));
}

void
vm_kmem_unmap_pa(unsigned long map_addr, size_t map_size)
{
    vm_kmem_free_va(map_addr, map_size);
}
