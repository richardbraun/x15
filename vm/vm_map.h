/*
 * Copyright (c) 2011-2017 Richard Braun.
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
 * Virtual memory map management.
 */

#ifndef _VM_VM_MAP_H
#define _VM_VM_MAP_H

#include <stdint.h>

#include <kern/init.h>
#include <kern/list.h>
#include <kern/mutex.h>
#include <kern/rbtree.h>
#include <machine/pmap.h>
#include <vm/vm_adv.h>
#include <vm/vm_inherit.h>
#include <vm/vm_prot.h>

/*
 * Mapping flags.
 *
 * Unless otherwise mentioned, these can also be used as map entry flags.
 */
#define VM_MAP_NOMERGE  0x10000
#define VM_MAP_FIXED    0x20000 /* Not an entry flag */

/*
 * Macro used to forge "packed" flags.
 */
#define VM_MAP_FLAGS(prot, maxprot, inherit, advice, mapflags)          \
    ((prot) | ((maxprot) << 4) | ((inherit) << 8) | ((advice) << 12)    \
     | (mapflags))

/*
 * Flags usable as map entry flags.
 *
 * Map entry flags also use the packed format.
 */
#define VM_MAP_ENTRY_MASK (VM_MAP_NOMERGE | 0xffff)

/*
 * Macros used to extract specific properties out of packed flags.
 */
#define VM_MAP_PROT(flags)      ((flags) & 0xf)
#define VM_MAP_MAXPROT(flags)   (((flags) & 0xf0) >> 4)
#define VM_MAP_INHERIT(flags)   (((flags) & 0xf00) >> 8)
#define VM_MAP_ADVICE(flags)    (((flags) & 0xf000) >> 12)

/*
 * Memory range descriptor.
 */
struct vm_map_entry {
    struct list list_node;
    struct rbtree_node tree_node;
    uintptr_t start;
    uintptr_t end;
    struct vm_object *object;
    uint64_t offset;
    int flags;
};

/*
 * Memory map.
 */
struct vm_map {
    struct mutex lock;
    struct list entry_list;
    struct rbtree entry_tree;
    unsigned int nr_entries;
    uintptr_t start;
    uintptr_t end;
    size_t size;
    struct vm_map_entry *lookup_cache;
    uintptr_t find_cache;
    size_t find_cache_threshold;
    struct pmap *pmap;
};

static inline struct vm_map *
vm_map_get_kernel_map(void)
{
    extern struct vm_map vm_map_kernel_map;

    return &vm_map_kernel_map;
}

/*
 * Create a virtual mapping.
 */
int vm_map_enter(struct vm_map *map, uintptr_t *startp,
                 size_t size, size_t align, int flags,
                 struct vm_object *object, uint64_t offset);

/*
 * Remove mappings from start to end.
 */
void vm_map_remove(struct vm_map *map, uintptr_t start, uintptr_t end);

/*
 * Create a VM map.
 */
int vm_map_create(struct vm_map **mapp);

/*
 * Display information about a memory map.
 */
void vm_map_info(struct vm_map *map);

/*
 * This init operation provides :
 *  - kernel mapping operations
 */
INIT_OP_DECLARE(vm_map_bootstrap);

/*
 * This init operation provides :
 *  - VM map creation
 *  - module fully initialized
 */
INIT_OP_DECLARE(vm_map_setup);

#endif /* _VM_VM_MAP_H */
