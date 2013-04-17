/*
 * Copyright (c) 2011, 2012, 2013 Richard Braun.
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

#include <kern/list.h>
#include <kern/mutex.h>
#include <kern/rbtree.h>
#include <kern/stdint.h>
#include <machine/pmap.h>

/*
 * Mapping flags and masks.
 *
 * All these flags can be used when creating a mapping. Most of them are
 * also used as map entry flags.
 */
#define VM_MAP_PROT_READ        0x00001
#define VM_MAP_PROT_WRITE       0x00002
#define VM_MAP_PROT_EXEC        0x00004
#define VM_MAP_PROT_ALL         (VM_MAP_PROT_READ       \
                                 | VM_MAP_PROT_WRITE    \
                                 | VM_MAP_PROT_EXEC)
#define VM_MAP_PROT_MASK        VM_MAP_PROT_ALL

#define VM_MAP_MAX_PROT_READ    (VM_MAP_PROT_READ << 4)
#define VM_MAP_MAX_PROT_WRITE   (VM_MAP_PROT_WRITE << 4)
#define VM_MAP_MAX_PROT_EXEC    (VM_MAP_PROT_EXEC << 4)
#define VM_MAP_MAX_PROT_ALL     (VM_MAP_MAX_PROT_READ       \
                                 | VM_MAP_MAX_PROT_WRITE    \
                                 | VM_MAP_MAX_PROT_EXEC)
#define VM_MAP_MAX_PROT_MASK    VM_MAP_MAX_PROT_ALL

#define VM_MAP_INHERIT_SHARE    0x00100
#define VM_MAP_INHERIT_COPY     0x00200
#define VM_MAP_INHERIT_NONE     0x00400
#define VM_MAP_INHERIT_MASK     (VM_MAP_INHERIT_SHARE   \
                                 | VM_MAP_INHERIT_COPY  \
                                 | VM_MAP_INHERIT_NONE)

#define VM_MAP_ADVISE_NORMAL    0x01000
#define VM_MAP_ADVISE_RAND      0x02000
#define VM_MAP_ADVISE_SEQ       0x04000
#define VM_MAP_ADVISE_MASK      (VM_MAP_ADVISE_NORMAL   \
                                 | VM_MAP_ADVISE_RAND   \
                                 | VM_MAP_ADVISE_SEQ)

#define VM_MAP_NOMERGE          0x10000
#define VM_MAP_FIXED            0x20000 /* Not an entry flag */

/*
 * Flags that can be used as map entry flags.
 */
#define VM_MAP_ENTRY_MASK       (VM_MAP_PROT_MASK       \
                                 | VM_MAP_MAX_PROT_MASK \
                                 | VM_MAP_INHERIT_MASK  \
                                 | VM_MAP_ADVISE_MASK   \
                                 | VM_MAP_NOMERGE)

/*
 * Memory range descriptor.
 */
struct vm_map_entry {
    struct list list_node;
    struct rbtree_node tree_node;
    unsigned long start;
    unsigned long end;
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
    unsigned long start;
    unsigned long end;
    size_t size;
    struct vm_map_entry *lookup_cache;
    unsigned long find_cache;
    size_t find_cache_threshold;
    struct pmap *pmap;
};

/*
 * Create a virtual mapping.
 */
int vm_map_enter(struct vm_map *map, struct vm_object *object, uint64_t offset,
                 unsigned long *startp, size_t size, size_t align, int flags);

/*
 * Remove mappings from start to end.
 */
void vm_map_remove(struct vm_map *map, unsigned long start, unsigned long end);

/*
 * Set up the vm_map module.
 */
void vm_map_setup(void);

/*
 * Create a VM map.
 */
int vm_map_create(struct vm_map **mapp);

/*
 * Display information about a memory map.
 */
void vm_map_info(struct vm_map *map);

#endif /* _VM_VM_MAP_H */
