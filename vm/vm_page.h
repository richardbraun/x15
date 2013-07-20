/*
 * Copyright (c) 2010, 2011, 2013 Richard Braun.
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

#include <kern/list.h>
#include <kern/macros.h>
#include <kern/param.h>
#include <kern/types.h>

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
 * True if the vm_page module is completely initialized, false otherwise
 * (in which case only vm_page_bootalloc() can be used for allocations).
 */
extern int vm_page_ready;

/*
 * Page usage types.
 *
 * Types aren't actually used. They merely provide statistics and debugging
 * information.
 */
#define VM_PAGE_FREE        0   /* Page unused */
#define VM_PAGE_RESERVED    1   /* Page reserved at boot time */
#define VM_PAGE_TABLE       2   /* Page is part of the page table */
#define VM_PAGE_PMAP        3   /* Page stores pmap-specific data */
#define VM_PAGE_KENTRY      4   /* Page stores kentry data (see vm_map) */
#define VM_PAGE_KMEM        5   /* Page stores kernel data (e.g. kmem slabs) */
#define VM_PAGE_OBJECT      6   /* Page is part of an object */

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

static inline phys_addr_t
vm_page_to_pa(const struct vm_page *page)
{
    return page->phys_addr;
}

/*
 * Load physical memory into the vm_page module at boot time.
 *
 * The avail_start and avail_end parameters are used to maintain a simple
 * heap for bootstrap allocations.
 *
 * All addresses must be page-aligned, and the start address must be
 * strictly greater than 0.
 */
void vm_page_load(const char *name, phys_addr_t start, phys_addr_t end,
                  phys_addr_t avail_start, phys_addr_t avail_end,
                  unsigned int seg_index, unsigned int seglist_prio);

/*
 * Allocate one physical page.
 *
 * This function is used to allocate physical memory at boot time, before the
 * vm_page module is ready, but after the physical memory has been loaded.
 */
phys_addr_t vm_page_bootalloc(void);

/*
 * Set up the vm_page module.
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
 */
struct vm_page * vm_page_alloc(unsigned int order, unsigned short type);

/*
 * Allocate physical pages from a specific segment.
 *
 * This function should only be called by architecture specific functions.
 */
struct vm_page * vm_page_alloc_seg(unsigned int order, unsigned int seg_index,
                                   unsigned short type);

/*
 * Release a block of 2^order physical pages.
 */
void vm_page_free(struct vm_page *page, unsigned int order);

/*
 * Display internal information about the module.
 */
void vm_page_info(void);

#endif /* _VM_VM_PAGE_H */
