/*
 * Copyright (c) 2011, 2012 Richard Braun.
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

#include <kern/kmem.h>
#include <vm/vm_map.h>
#include <vm/vm_kmem.h>
#include <vm/vm_phys.h>
#include <vm/vm_setup.h>

void
vm_setup(void)
{
    vm_kmem_setup();
    vm_phys_setup();
    kmem_setup();
    vm_map_bootstrap();
    vm_map_setup();
}
