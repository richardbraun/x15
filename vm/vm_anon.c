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

#include <kern/error.h>
#include <kern/init.h>
#include <kern/kmem.h>
#include <kern/list.h>
#include <kern/llsync.h>
#include <kern/macros.h>
#include <kern/mutex.h>
#include <kern/panic.h>
#include <kern/stddef.h>
#include <kern/stdint.h>
#include <vm/vm_anon.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_phys.h>

/*
 * Anonymous memory container.
 */
struct vm_anon {
    struct vm_object object;
    unsigned long nr_refs;
    size_t size;
};

/*
 * Anonymous pager operations.
 */
static void vm_anon_ref(struct vm_object *object);
static void vm_anon_unref(struct vm_object *object);
static int vm_anon_get(struct vm_object *object, uint64_t offset,
                       struct vm_page **pagep);

static struct vm_object_pager vm_anon_pager = {
    .ref = vm_anon_ref,
    .unref = vm_anon_unref,
    .get = vm_anon_get,
};

static struct kmem_cache vm_anon_cache;

void __init
vm_anon_setup(void)
{
    kmem_cache_init(&vm_anon_cache, "vm_anon", sizeof(struct vm_anon), 0,
                    NULL, NULL, NULL, 0);
}

struct vm_object *
vm_anon_create(size_t size)
{
    struct vm_anon *anon;

    anon = kmem_cache_alloc(&vm_anon_cache);

    if (anon == NULL)
        return NULL;

    vm_object_init(&anon->object, &vm_anon_pager);
    anon->nr_refs = 1;
    anon->size = size;
    return &anon->object;
}

static void
vm_anon_ref(struct vm_object *object)
{
    struct vm_anon *anon;

    anon = structof(object, struct vm_anon, object);

    /* TODO Use atomic operations */
    mutex_lock(&anon->object.lock);
    anon->nr_refs++;
    mutex_unlock(&anon->object.lock);
}

static void
vm_anon_unref(struct vm_object *object)
{
    struct vm_anon *anon;
    unsigned int nr_refs;

    anon = structof(object, struct vm_anon, object);

    mutex_lock(&anon->object.lock);
    anon->nr_refs--;
    nr_refs = anon->nr_refs;
    mutex_unlock(&anon->object.lock);

    if (nr_refs == 0)
        panic("vm_anon: destruction not implemented");
}

static int
vm_anon_get(struct vm_object *object, uint64_t offset,
            struct vm_page **pagep)
{
    struct vm_page *page;
    int error;

    page = vm_phys_alloc(0);

    if (page == NULL)
        return ERROR_NOMEM;

    error = vm_object_add(object, offset, page);

    if (error)
        goto error_object;

    *pagep = page;
    return 0;

error_object:
    vm_phys_free(page, 0);
    return error;
}
