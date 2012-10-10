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

#ifndef _X86_BOOT_H
#define _X86_BOOT_H

#include <lib/macros.h>

/*
 * The kernel is physically loaded at BOOT_OFFSET by the boot loader. It
 * will quickly establish the necessary mappings to run at KERNEL_OFFSET.
 *
 * See the linker script for more information.
 */
#define BOOT_OFFSET     DECL_CONST(0x100000, UL)

#ifdef __LP64__
#define KERNEL_OFFSET   DECL_CONST(0xffffffff80000000, UL)
#else /* __LP64__ */
#define KERNEL_OFFSET   DECL_CONST(0xc0000000, UL)
#endif /* __LP64__ */

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
 * Virtual to physical address translation macro.
 */
#define BOOT_VTOP(addr) ((unsigned long)(addr) - KERNEL_OFFSET)

/*
 * Functions and data used before paging is enabled must be part of the .boot
 * and .bootdata sections respectively, so that they use physical addresses.
 * Once paging is enabled, their access relies on the kernel identity mapping.
 */
#define __boot __section(".boot")
#define __bootdata __section(".bootdata")

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

#endif /* _X86_BOOT_H */
