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

#include <kern/rdxtree.h>
#include <kern/rdxtree.h>
#include <kern/stddef.h>
#include <kern/stdint.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>

struct vm_page *
vm_object_get(const struct vm_object *object, uint64_t offset)
{
    /* TODO Bump radix tree key size to 64-bits */

    return NULL;
}
