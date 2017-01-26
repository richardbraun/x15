/*
 * Copyright (c) 2011-2014 Richard Braun.
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

#include <kern/init.h>
#include <kern/kmem.h>
#include <kern/rdxtree.h>
#include <kern/percpu.h>
#include <machine/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>
#include <vm/vm_setup.h>

void __init
vm_setup(void)
{
    vm_page_setup();
    kmem_setup();
    vm_map_setup();
    rdxtree_setup();
    pmap_setup();
    percpu_setup();
}
