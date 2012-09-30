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

#ifndef _I386_BOOT_H
#define _I386_BOOT_H

/*
 * The kernel is physically loaded at BOOT_OFFSET by the boot loader. It
 * will quickly establish the necessary mappings to run at KERNEL_OFFSET.
 *
 * See the linker script for more information.
 */
#define BOOT_OFFSET     0x00100000
#define KERNEL_OFFSET   0xc0000000

/*
 * Size of the stack used to bootstrap the kernel.
 */
#define BOOT_STACK_SIZE 4096

/*
 * Address where the MP trampoline code is copied and run at.
 *
 * It must reside at a free location in the first segment and be page
 * aligned.
 */
#define BOOT_MP_TRAMPOLINE_ADDR 0x7000

#ifndef __ASSEMBLY__

#include <lib/macros.h>

/*
 * Access a variable during bootstrap, while still running at physical
 * addresses.
 */
#define BOOT_VTOP(var) \
    (*((typeof(var) *)((unsigned long)(&var) - KERNEL_OFFSET)))

/*
 * Address translation macros.
 */
#define BOOT_ADDR_VTOP(addr)    ((unsigned long)(addr) - KERNEL_OFFSET)
#define BOOT_ADDR_PTOV(addr)    ((unsigned long)(addr) + KERNEL_OFFSET)

/*
 * Functions used before paging is enabled must be part of the .boot section
 * so that they run at physical addresses. There is no .bootdata section; the
 * BOOT_VTOP() macro should be used instead.
 */
#define __boot __section(".boot")

/*
 * Boundaries of the .boot section.
 */
extern char _boot;
extern char _eboot;

/*
 * Size of the trampoline code used for APs.
 */
extern unsigned long boot_ap_size;

/*
 * Address of the MP trampoline code.
 */
void boot_ap_start(void);

#endif /* __ASSEMBLY__ */

#endif /* _I386_BOOT_H */
