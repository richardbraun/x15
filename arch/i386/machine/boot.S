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

#define __ASSEMBLY__

#include <machine/asm.h>
#include <machine/cpu.h>
#include <machine/boot.h>
#include <machine/multiboot.h>

/*
 * Convert a physical address in the .boot section to its real address in
 * the MP trampoline code.
 */
#define BOOT_MP_ADDR_PTOT(addr) (BOOT_MP_TRAMPOLINE_ADDR + (addr) \
                                 - boot_ap_start)

.section .boothdr, "wax"

 /*
  * Multiboot header.
  */
.align 4
DATA(boot_header)
 .long MULTIBOOT_OS_MAGIC
 .long MULTIBOOT_OS_FLAGS
 .long -(MULTIBOOT_OS_FLAGS + MULTIBOOT_OS_MAGIC)
END(boot_header)

/*
 * Entry point.
 */
ENTRY(_start)
 /*
  * Set up a simple GDT to conform to the multiboot specification.
  */
 lgdt boot_gdtr

 /*
  * Keep %eax and %ebx.
  */
 movw $0x10, %cx
 movw %cx, %ds
 movw %cx, %es
 movw %cx, %ss
 xorw %cx, %cx
 movw %cx, %fs
 movw %cx, %gs
 ljmp $8, $1f

1:
 /*
  * Set up the init stack.
  */
 movl $(init_stack + BOOT_STACK_SIZE - KERNEL_OFFSET), %esp
 movl %esp, %ebp

 /*
  * Enable paging.
  */
 pushl %ebx
 pushl %eax
 call init_paging
 movl %eax, %cr3
 movl %cr0, %eax
 orl $CPU_CR0_PG, %eax
 movl %eax, %cr0
 ljmp $8, $1f

1:
 /*
  * Reset the stack, use high addresses.
  */
 movl $(init_stack + BOOT_STACK_SIZE), %esp
 movl %esp, %ebp

 /*
  * Prevent stack tracing from searching previous frames.
  */
 pushl $0
 jmp init

 /*
  * Never reached.
  */
END(_start)

.section .boot, "wax"

DATA(boot_gdtr)
 .word (8 * 3)
 .long boot_gdt
END(boot_gdtr)

/*
 * This is where an AP runs after leaving the trampoline code.
 */
ENTRY(boot_ap_start32)
 /*
  * Set up the GDT again, because the current one is from the trampoline code
  * which isn't part of the identity mapping and won't be available once paging
  * is enabled.
  */
 lgdt boot_gdtr
 movw $0x10, %ax
 movw %ax, %ds
 movw %ax, %es
 movw %ax, %ss
 xorw %ax, %ax
 movw %ax, %fs
 movw %ax, %gs
 ljmp $8, $1f

1:
 /*
  * Set up the init stack.
  */
 movl $(init_ap_stack + BOOT_STACK_SIZE - KERNEL_OFFSET), %esp
 movl %esp, %ebp

 /*
  * Enable paging.
  */
 call init_ap_paging
 movl %eax, %cr3
 movl %cr0, %eax
 orl $CPU_CR0_PG, %eax
 movl %eax, %cr0
 ljmp $8, $1f

1:
 /*
  * Switch to the boot stack preallocated for this AP by the BSP.
  */
 movl (init_ap_boot_stack - KERNEL_OFFSET), %esp
 addl $BOOT_STACK_SIZE, %esp
 movl %esp, %ebp

 /*
  * Prevent stack tracing from searching previous frames.
  */
 pushl $0
 jmp init_ap

 /*
  * Never reached.
  */
END(boot_ap_start32)

/*
 * This section, including the GDT, is the MP trampoline code run by APs
 * on startup. It is copied at a fixed location in the first segment and
 * must enable protected mode to jump back into the kernel.
 */
.align 8
ENTRY(boot_ap_start)
 .code16
 cli
 xorw %ax, %ax
 movw %ax, %ds
 movw %ax, %es
 movw %ax, %fs
 movw %ax, %gs
 movw %ax, %ss
 lgdt BOOT_MP_ADDR_PTOT(boot_ap_gdtr)
 movl %cr0, %eax
 orl $CPU_CR0_PE, %eax
 movl %eax, %cr0
 ljmp $8, $BOOT_MP_ADDR_PTOT(1f)

.align 4
1:
 .code32
 movw $0x10, %ax
 movw %ax, %ds
 movw %ax, %es
 movw %ax, %ss
 xorw %ax, %ax
 movw %ax, %fs
 movw %ax, %gs
 ljmp $8, $boot_ap_start32
END(boot_ap_start)

DATA(boot_ap_gdtr)
 .word (8 * 3)
 .long BOOT_MP_ADDR_PTOT(boot_gdt)
END(boot_ap_gdtr)

.align 8
DATA(boot_gdt)
 /*
  * Null selector.
  */
 .word 0x0000
 .word 0x0000
 .word 0x0000
 .word 0x0000

 /*
  * Code segment selector.
  */
 .word 0xffff
 .word 0x0000
 .word 0x9a00
 .word 0x00cf

 /*
  * Data segment selector.
  */
 .word 0xffff
 .word 0x0000
 .word 0x9200
 .word 0x00cf
END(boot_gdt)

DATA(boot_ap_size)
 .long . - boot_ap_start
END(boot_ap_size)
