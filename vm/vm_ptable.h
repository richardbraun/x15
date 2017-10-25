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
 * TODO Comment.
 */

#ifndef _VM_VM_PTABLE_H
#define _VM_VM_PTABLE_H

#include <stddef.h>
#include <stdint.h>

#include <machine/pmap.h>
#include <machine/types.h>

struct vm_ptable_cpu_pt {
    pmap_pte_t *root;
};

typedef pmap_pte_t (*vm_ptable_make_pte_fn)(phys_addr_t pa, int prot);

/*
 * Translation level properties.
 */
struct vm_ptable_tlp {
    unsigned int skip;
    unsigned int bits;
    unsigned int ptes_per_pt;
    vm_ptable_make_pte_fn make_pte_fn;
    vm_ptable_make_pte_fn make_ll_pte_fn;
};

struct vm_ptable {
    struct vm_ptable_cpu_pt *cpu_pts[CONFIG_MAX_CPUS];
};

void vm_ptable_bootstrap(const struct vm_ptable_tlp *tlps, size_t nr_levels);

void vm_ptable_boot_build(struct vm_ptable *ptable);

void vm_ptable_boot_enter(struct vm_ptable *ptable, uintptr_t va,
                          phys_addr_t pa, size_t page_size);

pmap_pte_t * vm_ptable_boot_root(const struct vm_ptable *ptable);

#endif /* _VM_VM_PTABLE_H */
