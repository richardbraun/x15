/*
 * Copyright (c) 2010, 2012, 2013 Richard Braun.
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

.section .boot.hdr, "awx"
.code32

 /*
  * Multiboot header.
  */
ASM_DATA(boot_header)
 .long MULTIBOOT_OS_MAGIC
 .long MULTIBOOT_OS_FLAGS
 .long -(MULTIBOOT_OS_FLAGS + MULTIBOOT_OS_MAGIC)
ASM_END(boot_header)

/*
 * Entry point.
 */
ASM_ENTRY(_start)
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
 movl $(boot_stacks - KERNEL_OFFSET + BOOT_STACK_SIZE), %esp

#ifdef __LP64__
 call boot_check_long_mode
 call boot_setup_long_mode

 /*
  * At this point, the processor runs in long mode, but still uses the
  * compatibility mode code segment. Switch to 64-bit mode with a far return.
  */
 pushl $0x18
 pushl $1f
 lret

1:
 .code64
 movl %ebx, %edi
 movl %eax, %esi
#else /* __LP64__ */
 pushl %eax
 pushl %ebx
#endif /* __LP64__ */

 call boot_setup_paging

#ifdef __LP64__
 movq %rax, %cr3
 movq $(boot_stacks + BOOT_STACK_SIZE), %rsp
#else /* __LP64__ */
 movl %eax, %cr3
 movl %cr0, %eax
 orl $CPU_CR0_PG, %eax
 movl %eax, %cr0
 ljmp $8, $1f

1:
 movl $(boot_stacks + BOOT_STACK_SIZE), %esp
#endif /* __LP64__ */

 xorl %ebp, %ebp
 call boot_main

 /* Never reached */
 nop
ASM_END(_start)

.code32

ASM_DATA(boot_gdtr)
 .word boot_gdt_end - boot_gdt - 1
 .long boot_gdt
ASM_END(boot_gdtr)

#ifdef __LP64__

/*
 * The %eax and %ebx registers must be preserved.
 */

ASM_ENTRY(boot_check_long_mode)
 pushl %eax
 pushl %ebx
 movl $0x80000000, %eax
 cpuid
 cmpl $0x80000000, %eax
 jbe boot_no_long_mode
 movl $0x80000001, %eax
 cpuid
 testl $CPU_FEATURE4_LM, %edx
 jz boot_no_long_mode
 popl %ebx
 popl %eax
 ret
ASM_END(boot_check_long_mode)

ASM_ENTRY(boot_no_long_mode)
 hlt
 jmp boot_no_long_mode
ASM_END(boot_no_long_mode)

ASM_ENTRY(boot_setup_long_mode)
 /* Set PML4[0] */
 movl $boot_pdpt, %edx
 orl $(PMAP_PTE_RW | PMAP_PTE_P), %edx
 movl %edx, boot_pml4

 /* Set PDPT[0] through PDPT[3] */
 movl $boot_pdir, %edx
 orl $(PMAP_PTE_RW | PMAP_PTE_P), %edx
 movl $boot_pdpt, %edi
 movl $4, %ecx

1:
 movl %edx, (%edi)
 addl $PAGE_SIZE, %edx
 addl $8, %edi
 loop 1b

 /* Set PDIR[0] through PDIR[2047] */
 movl $(PMAP_PTE_PS | PMAP_PTE_RW | PMAP_PTE_P), %edx
 movl $boot_pdir, %edi
 movl $2048, %ecx

1:
 movl %edx, (%edi)
 addl $(1 << PMAP_L2_SHIFT), %edx
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
ASM_END(boot_setup_long_mode)
#endif /* __LP64__ */

/*
 * This is where an AP runs after leaving the trampoline code.
 */
ASM_ENTRY(boot_ap_start32)
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
 movl boot_ap_id, %esp
 incl %esp
 shll $BOOT_STACK_SHIFT, %esp
 addl $(boot_stacks - KERNEL_OFFSET), %esp

#ifdef __LP64__
 call boot_setup_long_mode
 pushl $0x18
 pushl $1f
 lret

1:
 .code64
#endif /* __LP64__ */

 call pmap_ap_setup_paging

#ifdef __LP64__
 movq %rax, %cr3
#else /* __LP64__ */
 movl %eax, %cr3
 movl %cr0, %eax
 orl $CPU_CR0_PG, %eax
 movl %eax, %cr0
 ljmp $8, $1f

1:
#endif /* __LP64__ */

 movl boot_ap_id, %esp
 incl %esp
 shll $BOOT_STACK_SHIFT, %esp

#ifdef __LP64__
 addq $boot_stacks, %rsp
#else /* __LP64__ */
 addl $boot_stacks, %esp
#endif /* __LP64__ */

 xorl %ebp, %ebp
 call boot_ap_main

 /* Never reached */
 nop
ASM_END(boot_ap_start32)

.code32

/*
 * This part, including the GDT, is the MP trampoline code run by APs
 * on startup. It is copied at a fixed location in the first segment and
 * must enable protected mode to jump back into the kernel.
 */
ASM_ENTRY(boot_mp_trampoline)
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
ASM_END(boot_mp_trampoline)

ASM_DATA(boot_ap_gdtr)
 .word boot_gdt_end - boot_gdt - 1
 .long BOOT_MP_ADDR_PTOT(boot_gdt)
ASM_END(boot_ap_gdtr)

ASM_DATA(boot_gdt)
 .quad 0x0000000000000000   /* Null selector */
 .quad 0x00cf9a000000ffff   /* Code segment selector */
 .quad 0x00cf92000000ffff   /* Data segment selector */

#ifdef __LP64__
 .quad 0x00209a0000000000   /* 64-bit code segment selector */
#endif /* __LP64__ */
ASM_END(boot_gdt)
boot_gdt_end:

ASM_DATA(boot_mp_trampoline_size)
 .long . - boot_mp_trampoline
ASM_END(boot_mp_trampoline_size)
