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
 */

#include <kern/assert.h>
#include <kern/error.h>
#include <kern/llsync.h>
#include <kern/mutex.h>
#include <kern/param.h>
#include <kern/rdxtree.h>
#include <kern/stddef.h>
#include <kern/stdint.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>

int
vm_object_add(struct vm_object *object, uint64_t offset, struct vm_page *page)
{
    int error;

    mutex_lock(&object->lock);

    error = rdxtree_insert(&object->pages, offset >> PAGE_SHIFT, page);

    if (!error)
        object->nr_pages++;

    mutex_unlock(&object->lock);

    assert(!error || (error == ERROR_NOMEM));

    return error;
}

struct vm_page *
vm_object_get(const struct vm_object *object, uint64_t offset)
{
    struct vm_page *page;

    llsync_read_enter();

    /* TODO Handle page state changes */
    page = rdxtree_lookup(&object->pages, offset >> PAGE_SHIFT);

    llsync_read_leave();

    return page;
}
