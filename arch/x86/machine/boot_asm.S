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
#include <machine/param.h>
#include <machine/pmap.h>

/*
 * Convert a physical address in the .boot section to its real address in
 * the MP trampoline code.
 */
#define BOOT_MP_ADDR_PTOT(addr) (BOOT_MP_TRAMPOLINE_ADDR + (addr) \
                                 - boot_mp_trampoline)

.section .init.hdr, "awx"
.code32

 /*
  * Multiboot header.
  */
DATA(boot_header)
 .long MULTIBOOT_OS_MAGIC
 .long MULTIBOOT_OS_FLAGS
 .long -(MULTIBOOT_OS_FLAGS + MULTIBOOT_OS_MAGIC)
END(boot_header)

/*
 * Entry point.
 */
ENTRY(_start)
 lgdt boot_gdtr

 /* Keep %eax and %ebx */
 movl $0x10, %ecx
 movl %ecx, %ds
 movl %ecx, %es
 movl %ecx, %ss
 xorl %ecx, %ecx
 movl %ecx, %fs
 movl %ecx, %gs
 ljmp $8, $1f

1:
 movl $(boot_stack + BOOT_STACK_SIZE), %esp
 movl %esp, %ebp

#ifdef __LP64__
 call boot_setup_long_mode

 /*
  * At this point, the processor runs in long mode, but still uses the compatibility
  * mode code segment. Switch to 64-bit mode with a far return.
  */
 pushl $0x18
 pushl $1f
 lret
1:
#endif

 pushl %ebx
 pushl %eax
 call boot_setup_paging
 movl %eax, %cr3
 movl %cr0, %eax
 orl $CPU_CR0_PG, %eax
 movl %eax, %cr0
 ljmp $8, $1f

1:
#ifdef __LP64__
 hlt
#else /* __LP64__ */
 /* Prevent stack tracing from searching previous frames */
 pushl $0
 jmp boot_main
#endif /* __LP64__ */

 /* Never reached */
END(_start)

DATA(boot_gdtr)
 .word boot_gdt_end - boot_gdt - 1
 .long boot_gdt
END(boot_gdtr)

#ifdef __LP64__
/*
 * The %eax and %ebx registers must be preserved.
 */
ENTRY(boot_setup_long_mode)
 /* Set PML4[0] */
 movl $boot_pdpt, %edx
 orl $(PMAP_PTE_WRITE | PMAP_PTE_PRESENT), %edx
 movl %edx, boot_pml4

 /* Set PDPT[0] through PDPT[3] */
 movl $boot_pdir, %edx
 orl $(PMAP_PTE_WRITE | PMAP_PTE_PRESENT), %edx
 movl $boot_pdpt, %edi
 movl $4, %ecx

1:
 movl %edx, (%edi)
 addl $PAGE_SIZE, %edx
 addl $8, %edi
 loop 1b

 /* Set PDIR[0] through PDIR[2047] */
 movl $(PMAP_PTE_PAGE_SIZE | PMAP_PTE_WRITE | PMAP_PTE_PRESENT), %edx
 movl $boot_pdir, %edi
 movl $2048, %ecx

1:
 movl %edx, (%edi)
 addl $(1 << PMAP_PDE_SHIFT), %edx
 addl $8, %edi
 loop 1b

 /* Switch to long mode */
 movl %eax, %edi
 movl %cr4, %eax
 orl $CPU_CR4_PAE, %eax
 movl %eax, %cr4
 movl $boot_pml4, %eax
 movl %eax, %cr3
 movl $CPU_MSR_EFER, %ecx
 rdmsr
 orl $CPU_EFER_LME, %eax
 wrmsr
 movl %cr0, %eax
 orl $CPU_CR0_PG, %eax
 movl %eax, %cr0
 ljmp $8, $1f

1:
 movl %edi, %eax
 ret
END(boot_setup_long_mode)
#endif /* __LP64__ */

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
 movl $0x10, %eax
 movl %eax, %ds
 movl %eax, %es
 movl %eax, %ss
 xorl %eax, %eax
 movl %eax, %fs
 movl %eax, %gs
 ljmp $8, $1f

1:
 movl $(boot_ap_stack + BOOT_STACK_SIZE), %esp
 movl %esp, %ebp
 call pmap_ap_setup_paging
 movl %eax, %cr3
 movl %cr0, %eax
 orl $CPU_CR0_PG, %eax
 movl %eax, %cr0
 ljmp $8, $1f

1:
 /* Switch to the boot stack preallocated for this AP by the BSP */
 movl boot_ap_stack_addr, %esp
 addl $BOOT_STACK_SIZE, %esp
 movl %esp, %ebp

 /* Prevent stack tracing from searching previous frames */
 pushl $0
 jmp boot_ap

 /* Never reached */
END(boot_ap_start32)

/*
 * This section, including the GDT, is the MP trampoline code run by APs
 * on startup. It is copied at a fixed location in the first segment and
 * must enable protected mode to jump back into the kernel.
 */
ENTRY(boot_mp_trampoline)
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
 movl $0x10, %eax
 movl %eax, %ds
 movl %eax, %es
 movl %eax, %ss
 xorl %eax, %eax
 movl %eax, %fs
 movl %eax, %gs
 ljmp $8, $boot_ap_start32
END(boot_mp_trampoline)

DATA(boot_ap_gdtr)
 .word boot_gdt_end - boot_gdt - 1
 .long BOOT_MP_ADDR_PTOT(boot_gdt)
END(boot_ap_gdtr)

DATA(boot_gdt)
 .quad 0x0000000000000000   /* Null selector */
 .quad 0x00cf9a000000ffff   /* Code segment selector */
 .quad 0x00cf92000000ffff   /* Data segment selector */

#ifdef __LP64__
 .quad 0x00209a0000000000   /* 64-bit code segment selector */
#endif /* __LP64__ */
END(boot_gdt)

DATA(boot_mp_trampoline_size)
 .long . - boot_mp_trampoline
END(boot_mp_trampoline_size)
