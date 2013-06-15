/*
 * Copyright (c) 2013 Richard Braun.
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
 * Virtual memory object.
 *
 * VM objects are the primary interface between a VM map and a pager. They
 * can be entered in a VM map ("mapped") and, on page fault, the VM system
 * requests the actual data from the the backing store pager. The physical
 * pages used to store those data are then inserted into the appropriate
 * object.
 */

#ifndef _VM_VM_OBJECT_H
#define _VM_VM_OBJECT_H

#include <kern/list.h>
#include <kern/mutex.h>
#include <kern/rdxtree.h>
#include <kern/stdint.h>

struct vm_object_pager;

/*
 * Memory object.
 */
struct vm_object {
    struct mutex lock;
    struct rdxtree pages;
    unsigned long nr_pages;
    struct vm_object_pager *pager;
};

/*
 * Pager operations on an object.
 */
struct vm_object_pager {
    void (*ref)(struct vm_object *object);
    void (*unref)(struct vm_object *object);
    int (*get)(struct vm_object *object, uint64_t offset, struct list *pages,
               int access_prot, int advice);
};

static inline void
vm_object_init(struct vm_object *object, struct vm_object_pager *pager)
{
    mutex_init(&object->lock);
    rdxtree_init(&object->pages);
    object->nr_pages = 0;
    object->pager = pager;
}

#endif /* _VM_VM_OBJECT_H */
