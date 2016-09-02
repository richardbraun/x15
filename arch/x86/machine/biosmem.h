/*
 * Copyright (c) 2010-2016 Richard Braun.
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

#ifndef _X86_BIOSMEM_H
#define _X86_BIOSMEM_H

#include <stdbool.h>

#include <kern/types.h>
#include <machine/multiboot.h>

/*
 * Address where the address of the Extended BIOS Data Area segment can be
 * found.
 */
#define BIOSMEM_EBDA_PTR 0x40e

/*
 * Significant low memory addresses.
 *
 * The first 64 KiB are reserved for various reasons (e.g. to preserve BIOS
 * data and to work around data corruption on some hardware).
 */
#define BIOSMEM_BASE        0x010000
#define BIOSMEM_BASE_END    0x0a0000
#define BIOSMEM_EXT_ROM     0x0e0000
#define BIOSMEM_ROM         0x0f0000
#define BIOSMEM_END         0x100000

/*
 * Early initialization of the biosmem module.
 *
 * This function processes the given multiboot data for BIOS-provided
 * memory information, and sets up a bootstrap physical page allocator.
 *
 * It is called before paging is enabled.
 */
void biosmem_bootstrap(struct multiboot_raw_info *mbi);

/*
 * Allocate contiguous physical pages during bootstrap.
 *
 * This function is called before paging is enabled. The pages returned
 * are guaranteed to be part of the direct physical mapping when paging
 * is enabled.
 *
 * This function should only be used to allocate initial page table pages.
 * Those pages are later loaded into the VM system (as reserved pages)
 * which means they can be freed like other regular pages. Users should
 * fix up the type of those pages once the VM system is initialized.
 */
void * biosmem_bootalloc(unsigned int nr_pages);

/*
 * Set the bootstrap allocation policy.
 *
 * The policy can be changed at any time while the bootstrap allocator
 * is usable.
 */
void biosmem_set_bootalloc_policy(bool topdown);

/*
 * Return the limit of physical memory that can be directly mapped.
 */
phys_addr_t biosmem_directmap_end(void);

/*
 * Set up physical memory based on the information obtained during bootstrap
 * and load it in the VM system.
 */
void biosmem_setup(void);

/*
 * Free all usable memory.
 *
 * This includes ranges that weren't part of the bootstrap allocator initial
 * heap, e.g. because they contained boot data. Any boot data to keep must
 * be saved before calling this function.
 */
void biosmem_free_usable(void);

#endif /* _X86_BIOSMEM_H */
