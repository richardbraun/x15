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
 * Anonymous memory.
 *
 * Historically, this memory type refers to memory that isn't backed by a file
 * on Unix, and as a result has no name.
 */

#ifndef _VM_VM_ANON_H
#define _VM_VM_ANON_H

#include <kern/stddef.h>
#include <vm/vm_object.h>

/*
 * Initialize the vm_anon module.
 */
void vm_anon_setup(void);

/*
 * Create an anonymous memory object.
 */
struct vm_object * vm_anon_create(size_t size);
#endif /* _VM_VM_ANON_H */
