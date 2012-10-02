/*
 * Copyright (c) 2010, 2012 Richard Braun.
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

#ifndef _X86_MULTIBOOT_H
#define _X86_MULTIBOOT_H

/*
 * Magic number provided by the OS to the boot loader.
 */
#define MULTIBOOT_OS_MAGIC 0x1badb002

/*
 * Multiboot flags requesting services from the boot loader.
 */
#define MULTIBOOT_OS_MEMORY_INFO    0x2

#define MULTIBOOT_OS_FLAGS MULTIBOOT_OS_MEMORY_INFO

/*
 * Magic number to identify a multiboot compliant boot loader.
 */
#define MULTIBOOT_LOADER_MAGIC 0x2badb002

/*
 * Multiboot flags set by the boot loader.
 */
#define MULTIBOOT_LOADER_MEMORY     0x01
#define MULTIBOOT_LOADER_CMDLINE    0x04
#define MULTIBOOT_LOADER_MODULES    0x08
#define MULTIBOOT_LOADER_MMAP       0x40

#ifndef __ASSEMBLY__

#include <lib/macros.h>
#include <lib/stdint.h>

/*
 * A multiboot module.
 */
struct multiboot_module {
    void *mod_start;
    void *mod_end;
    char *string;
    uint32_t reserved;
} __packed;

/*
 * Memory map entry.
 */
struct multiboot_mmap_entry {
    uint32_t size;
    uint64_t base_addr;
    uint64_t length;
    uint32_t type;
} __packed;

/*
 * Multiboot information structure to get data passed by the boot loader.
 */
struct multiboot_info {
    uint32_t flags;
    uint32_t mem_lower;
    uint32_t mem_upper;
    uint32_t unused0;
    char *cmdline;
    uint32_t mods_count;
    struct multiboot_module *mods_addr;
    uint32_t unused1[4];
    uint32_t mmap_length;
    void *mmap_addr;
    uint32_t unused2[9];
} __packed;

#endif /* __ASSEMBLY__ */

#endif /* _X86_MULTIBOOT_H */
