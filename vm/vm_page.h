/*
 * Copyright (c) 2010, 2011 Richard Braun.
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

#ifndef _VM_VM_PAGE_H
#define _VM_VM_PAGE_H

#include <lib/list.h>
#include <lib/macros.h>
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
 * Physical page descriptor.
 */
struct vm_page {
    struct list node;
    unsigned short seg_index;
    unsigned short order;
    vm_phys_t phys_addr;
};

static inline vm_phys_t
vm_page_to_pa(const struct vm_page *page)
{
    return page->phys_addr;
}

#endif /* _VM_VM_PAGE_H */
