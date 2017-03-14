/*
 * Copyright (c) 2010-2014 Richard Braun.
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

#include <kern/macros.h>
#include <machine/param.h>

/*
 * Macros used by the very early panic functions.
 */
#define BOOT_CGAMEM     0xb8000
#define BOOT_CGACHARS   (80 * 25)
#define BOOT_CGACOLOR   0x7

/*
 * The kernel is physically loaded at BOOT_OFFSET by the boot loader. It
 * is divided in two parts: the .boot section which uses physical addresses
 * and the main kernel code and data at VM_KERNEL_OFFSET.
 *
 * See the linker script for more information.
 */
#define BOOT_OFFSET DECL_CONST(0x100000, UL)

/*
 * Virtual to physical address translation macro.
 */
#define BOOT_VTOP(addr) ((addr) - VM_KERNEL_OFFSET)

/*
 * Address where the MP trampoline code is copied and run at.
 *
 * It must reside at a free location in the first segment and be page
 * aligned.
 */
#define BOOT_MP_TRAMPOLINE_ADDR 0x7000

#ifndef __ASSEMBLER__

#include <machine/multiboot.h>
#include <machine/pmap.h>

/*
 * Functions and data used before paging is enabled must be part of the .boot
 * and .bootdata sections respectively, so that they use physical addresses.
 * Once paging is enabled, their access relies on the kernel identity mapping.
 */
#define __boot __section(".boot.text")
#define __bootdata __section(".boot.data")

/*
 * Boundaries of the .boot section.
 */
extern char _boot;
extern char _eboot;

extern char boot_stack[STACK_SIZE];
extern char boot_ap_stack[STACK_SIZE];

/*
 * This variable contains the CPU ID of an AP during early initialization.
 */
extern unsigned int boot_ap_id;

/*
 * Size of the trampoline code used for APs.
 */
extern uint32_t boot_mp_trampoline_size;

/*
 * Address of the MP trampoline code.
 */
void boot_mp_trampoline(void);

/*
 * Helper functions available before paging is enabled.
 *
 * Any memory passed to these must also be accessible without paging.
 */
void * boot_memmove(void *dest, const void *src, size_t n);
void * boot_memset(void *s, int c, size_t n);
size_t boot_strlen(const char *s);
void __noreturn boot_panic(const char *s);

/*
 * This function is called by the bootstrap code before paging is enabled.
 * It establishes a direct mapping of the kernel at virtual addresses and
 * returns the physical address of the page directory. It is up to the
 * caller to actually enable paging.
 */
pmap_pte_t * boot_setup_paging(struct multiboot_raw_info *mbi,
                               unsigned long eax);

/*
 * Main entry point, called directly after basic paging is initialized.
 */
void boot_main(void);

/*
 * Entry point for APs.
 */
void boot_ap_main(void);

#endif /* __ASSEMBLER__ */

#endif /* _X86_BOOT_H */
