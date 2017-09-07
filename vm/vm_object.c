/*
 * Copyright (c) 2017 Richard Braun.
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
 * This implementation is based on the paper "A lockless pagecache in Linux"
 * by Nick Piggin. It allows looking up pages without contention on VM objects.
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include <kern/init.h>
#include <kern/llsync.h>
#include <kern/mutex.h>
#include <kern/rdxtree.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <machine/page.h>

struct vm_object vm_object_kernel_object;

static int __init
vm_object_setup(void)
{
    return 0;
}

INIT_OP_DEFINE(vm_object_setup,
               INIT_OP_DEP(mutex_setup, true),
               INIT_OP_DEP(rdxtree_setup, true),
               INIT_OP_DEP(vm_page_setup, true));

void __init
vm_object_init(struct vm_object *object, uint64_t size)
{
    assert(vm_page_aligned(size));

    mutex_init(&object->lock);
    rdxtree_init(&object->pages, 0);
    object->size = size;
    object->nr_pages = 0;
}

int
vm_object_insert(struct vm_object *object, struct vm_page *page,
                 uint64_t offset)
{
    int error;

    assert(vm_page_aligned(offset));

    /*
     * The page may have no references. Add one before publishing
     * so that concurrent lookups succeed.
     */
    vm_page_ref(page);

    mutex_lock(&object->lock);

    if (offset >= object->size) {
        error = ERROR_INVAL;
        goto error;
    }

    error = rdxtree_insert(&object->pages, vm_page_btop(offset), page);

    if (error) {
        goto error;
    }

    vm_page_link(page, object, offset);
    object->nr_pages++;
    assert(object->nr_pages != 0);

    mutex_unlock(&object->lock);

    return 0;

error:
    mutex_unlock(&object->lock);

    vm_page_unref(page);

    return error;
}

void
vm_object_remove(struct vm_object *object, uint64_t start, uint64_t end)
{
    struct vm_page *page;
    uint64_t offset;

    assert(vm_page_aligned(start));
    assert(vm_page_aligned(end));
    assert(start <= end);

    mutex_lock(&object->lock);

    for (offset = start; offset < end; offset += PAGE_SIZE) {
        page = rdxtree_remove(&object->pages, vm_page_btop(offset));

        if (page == NULL) {
            continue;
        }

        vm_page_unlink(page);
        vm_page_unref(page);
        assert(object->nr_pages != 0);
        object->nr_pages--;
    }

    mutex_unlock(&object->lock);
}

struct vm_page *
vm_object_lookup(struct vm_object *object, uint64_t offset)
{
    struct vm_page *page;
    int error;

    llsync_read_enter();

    do {
        page = rdxtree_lookup(&object->pages, vm_page_btop(offset));

        if (page == NULL) {
            break;
        }

        error = vm_page_tryref(page);
    } while (error);

    llsync_read_exit();

    return page;
}
