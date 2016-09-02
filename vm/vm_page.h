/*
 * Copyright (c) 2010-2014 Richard Braun.
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
 * Physical page management.
 */

#ifndef _VM_VM_PAGE_H
#define _VM_VM_PAGE_H

#include <kern/assert.h>
#include <kern/list.h>
#include <kern/log2.h>
#include <kern/macros.h>
#include <kern/param.h>
#include <kern/stddef.h>
#include <kern/types.h>
#include <machine/pmap.h>

/*
 * Address/page conversion and rounding macros (not inline functions to
 * be easily usable on both virtual and physical addresses, which may not
 * have the same type size).
 */
#define vm_page_atop(addr)      ((addr) >> PAGE_SHIFT)
#define vm_page_ptoa(page)      ((page) << PAGE_SHIFT)
#define vm_page_trunc(addr)     P2ALIGN(addr, PAGE_SIZE)
#define vm_page_round(addr)     P2ROUND(addr, PAGE_SIZE)
#define vm_page_aligned(addr)   P2ALIGNED(addr, PAGE_SIZE)

/*
 * Segment selectors.
 *
 * Selector-to-segment-list translation table :
 * DMA          DMA
 * DMA32        DMA32 DMA
 * DIRECTMAP    DIRECTMAP DMA32 DMA
 * HIGHMEM      HIGHMEM DIRECTMAP DMA32 DMA
 */
#define VM_PAGE_SEL_DMA         0
#define VM_PAGE_SEL_DMA32       1
#define VM_PAGE_SEL_DIRECTMAP   2
#define VM_PAGE_SEL_HIGHMEM     3

/*
 * Page usage types.
 *
 * Failing to allocate pmap pages will cause a kernel panic.
 * TODO Obviously, this needs to be addressed, e.g. with a reserved pool of
 * pages.
 */
#define VM_PAGE_FREE        0   /* Page unused */
#define VM_PAGE_RESERVED    1   /* Page reserved at boot time */
#define VM_PAGE_TABLE       2   /* Page is part of the page table */
#define VM_PAGE_PMAP        3   /* Page stores pmap-specific data */
#define VM_PAGE_KMEM        4   /* Page is part of a kmem slab */
#define VM_PAGE_OBJECT      5   /* Page is part of a VM object */
#define VM_PAGE_KERNEL      6   /* Type for generic kernel allocations */

/*
 * Physical page descriptor.
 */
struct vm_page {
    struct list node;
    unsigned short type;
    unsigned short seg_index;
    unsigned short order;
    phys_addr_t phys_addr;
    void *slab_priv;
};

static inline unsigned short
vm_page_type(const struct vm_page *page)
{
    return page->type;
}

void vm_page_set_type(struct vm_page *page, unsigned int order,
                      unsigned short type);

static inline unsigned int
vm_page_order(size_t size)
{
    return iorder2(vm_page_atop(vm_page_round(size)));
}

static inline phys_addr_t
vm_page_to_pa(const struct vm_page *page)
{
    return page->phys_addr;
}

static inline unsigned long
vm_page_direct_va(phys_addr_t pa)
{
    assert(pa < VM_PAGE_DIRECTMAP_LIMIT);
    return ((unsigned long)pa + VM_MIN_DIRECTMAP_ADDRESS);
}

static inline phys_addr_t
vm_page_direct_pa(unsigned long va)
{
    assert(va >= VM_MIN_DIRECTMAP_ADDRESS);
    assert(va < VM_MAX_DIRECTMAP_ADDRESS);
    return (va - VM_MIN_DIRECTMAP_ADDRESS);
}

static inline void *
vm_page_direct_ptr(const struct vm_page *page)
{
    return (void *)vm_page_direct_va(vm_page_to_pa(page));
}

/*
 * Load physical memory into the vm_page module at boot time.
 *
 * All addresses must be page-aligned. Segments can be loaded in any order.
 */
void vm_page_load(unsigned int seg_index, phys_addr_t start, phys_addr_t end);

/*
 * Load available physical memory into the vm_page module at boot time.
 *
 * The segment referred to must have been loaded with vm_page_load
 * before loading its heap.
 */
void vm_page_load_heap(unsigned int seg_index, phys_addr_t start,
                       phys_addr_t end);

/*
 * Return true if the vm_page module is completely initialized, false
 * otherwise, in which case only vm_page_bootalloc() can be used for
 * allocations.
 */
int vm_page_ready(void);

/*
 * Set up the vm_page module.
 *
 * Architecture-specific code must have loaded segments before calling this
 * function. Segments must comply with the selector-to-segment-list table,
 * e.g. HIGHMEM is loaded if and only if DIRECTMAP, DMA32 and DMA are loaded,
 * notwithstanding segment aliasing.
 *
 * Once this function returns, the vm_page module is ready, and normal
 * allocation functions can be used.
 */
void vm_page_setup(void);

/*
 * Make the given page managed by the vm_page module.
 *
 * If additional memory can be made usable after the VM system is initialized,
 * it should be reported through this function.
 */
void vm_page_manage(struct vm_page *page);

/*
 * Return the page descriptor for the given physical address.
 */
struct vm_page * vm_page_lookup(phys_addr_t pa);

/*
 * Allocate a block of 2^order physical pages.
 *
 * The selector is used to determine the segments from which allocation can
 * be attempted.
 */
struct vm_page * vm_page_alloc(unsigned int order, unsigned int selector,
                               unsigned short type);

/*
 * Release a block of 2^order physical pages.
 */
void vm_page_free(struct vm_page *page, unsigned int order);

/*
 * Return the name of the given segment.
 */
const char * vm_page_seg_name(unsigned int seg_index);

/*
 * Display internal information about the module.
 */
void vm_page_info(void);

#endif /* _VM_VM_PAGE_H */
