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

#ifndef _I386_INIT_H
#define _I386_INIT_H

#include <lib/macros.h>
#include <lib/stdint.h>
#include <machine/boot.h>
#include <machine/multiboot.h>
#include <machine/pmap.h>

/*
 * Stack used to bootstrap the kernel.
 */
extern char init_stack[BOOT_STACK_SIZE];

/*
 * Common stack used by APs to bootstrap.
 */
extern char init_ap_stack[BOOT_STACK_SIZE];

/*
 * This variable contains the CPU ID of an AP during its early boot.
 */
extern unsigned long init_ap_id;

/*
 * After its early boot, an AP enables paging and jumps to virtual
 * addresses. At this point, it switches to a per-AP preallocated
 * stack. This variable contains the (virtual) address of that stack.
 */
extern unsigned long init_ap_boot_stack;

/*
 * Print the given message and halt the system immediately.
 *
 * This function allows early initialization code to print something helpful
 * before printk is available.
 */
void __noreturn init_panic(const char *s);

/*
 * This function is called by the bootstrap code before paging is enabled.
 * It establishes a direct mapping of the kernel at virtual addresses and
 * returns the physical address of the page directory. It is up to the
 * caller to actually enable paging.
 */
pmap_pte_t * init_paging(uint32_t eax, const struct multiboot_info *mbi);

/*
 * This function is called by the AP bootstrap code before paging is enabled.
 * It merely returns the physical address of the already existing kernel page
 * directory.
 */
pmap_pte_t * init_ap_paging(void);

/*
 * Main entry point, called directly after basic paging is initialized.
 */
void init(void);

/*
 * Entry point for APs.
 */
void init_ap(void);

#endif /* _I386_INIT_H */
