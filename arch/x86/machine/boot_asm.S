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
#include <machine/page.h>
#include <machine/pmap.h>

/*
 * Boot GDT segment selectors.
 */
#define BOOT_GDT_SEL_NULL   0
#define BOOT_GDT_SEL_CODE   8
#define BOOT_GDT_SEL_DATA   16
#define BOOT_GDT_SEL_CODE64 24
#define BOOT_GDT_SEL_TLS    24

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
 movl $BOOT_GDT_SEL_DATA, %ecx
 movl %ecx, %ds
 movl %ecx, %es
 movl %ecx, %ss
 xorl %ecx, %ecx
 movl %ecx, %fs
 movl %ecx, %gs
 ljmp $BOOT_GDT_SEL_CODE, $1f

1:
 movl $(boot_stack + BOOT_STACK_SIZE), %esp

#ifdef __LP64__
 call boot_check_long_mode
 call boot_setup_tls
 call boot_setup_long_mode

 /*
  * At this point, the processor runs in long mode, but still uses the
  * compatibility mode code segment. Switch to 64-bit mode with a far return.
  */
 pushl $BOOT_GDT_SEL_CODE64
 pushl $1f
 lret

1:
 .code64
 movl %ebx, %edi
 movl %eax, %esi
#else /* __LP64__ */
 call boot_build_tls_seg_desc
 movl $BOOT_GDT_SEL_TLS, %ecx
 movl %ecx, %gs

 pushl %eax
 pushl %ebx
#endif /* __LP64__ */

 call boot_setup_paging

#ifdef __LP64__
 movq %rax, %cr3
 movq $(boot_stack + BOOT_STACK_SIZE), %rsp
#else /* __LP64__ */
 movl %eax, %cr3
 movl %cr0, %eax
 orl $CPU_CR0_PG, %eax
 movl %eax, %cr0
 ljmp $BOOT_GDT_SEL_CODE, $1f

1:
 movl $(boot_stack + BOOT_STACK_SIZE), %esp
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
 movl $boot_panic_long_mode_msg, %esi
 movl $BOOT_CGAMEM, %edi
 movl $(BOOT_CGAMEM + (BOOT_CGACHARS * 2)), %edx
 movw $(BOOT_CGACOLOR << 8), %ax

1:
 movb (%esi), %al
 testb %al, %al
 jz 1f
 movw %ax, (%edi)
 incl %esi
 add $2, %edi
 cmpl %edx, %edi
 jae 2f
 jmp 1b

1:
 cmpl %edx, %edi
 jae 2f
 movw $((BOOT_CGACOLOR << 8) + ' '), (%edi)
 add $2, %edi
 jmp 1b

2:
 hlt
 jmp 2b
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
 addl $(1 << PMAP_L1_SKIP), %edx
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
 ljmp $BOOT_GDT_SEL_CODE, $1f

1:
 movl %edi, %eax
 ret
ASM_END(boot_setup_long_mode)

ASM_ENTRY(boot_setup_tls)
 pushl %eax
 movl $boot_tls_seg, %eax
 movl $0, %edx
 movl $CPU_MSR_GSBASE, %ecx
 wrmsr
 popl %eax
 ret
ASM_END(boot_setup_tls)

#else /* __LP64__ */

/*
 * Complete the temporary boot TLS segment descriptor and copy it into
 * the boot GDT.
 *
 * The %eax and %ebx registers must be preserved.
 */
ASM_ENTRY(boot_build_tls_seg_desc)
 pushl %eax

 /* Load boot_tls_seg_desc address */
 movl $boot_tls_seg_desc, %ecx

 /* Add the base 15:0 bits to boot_tls_seg_desc.low */
 movl $boot_tls_seg, %eax
 shll $16, %eax
 orl %eax, (%ecx)

 /* Add the base 23:16 bits to boot_tls_seg_desc.high */
 movl $boot_tls_seg, %eax
 shrl $16, %eax
 andl $0xff, %eax
 orl %eax, 4(%ecx)

 /* Add the base 31:24 bits to boot_tls_seg_desc.high */
 movl $boot_tls_seg, %eax
 andl $0xff000000, %eax
 orl %eax, 4(%ecx)

 /* Load boot_gdt[BOOT_GDT_SEL_TLS] address */
 movl $boot_gdt + BOOT_GDT_SEL_TLS, %edx

 /* Set boot_gdt[BOOT_GDT_SEL_TLS].low */
 movl (%ecx), %eax
 movl %eax, (%edx)

 /* Set boot_gdt[BOOT_GDT_SEL_TLS].high */
 movl 4(%ecx), %eax
 movl %eax, 4(%edx)

 popl %eax
 ret
ASM_END(boot_build_tls_seg_desc)

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
 movl $BOOT_GDT_SEL_DATA, %eax
 movl %eax, %ds
 movl %eax, %es
 movl %eax, %ss
 xorl %eax, %eax
 movl %eax, %fs
 movl $BOOT_GDT_SEL_TLS, %eax
 movl %eax, %gs
 ljmp $BOOT_GDT_SEL_CODE, $1f

1:
 movl $(boot_ap_stack + BOOT_STACK_SIZE), %esp

#ifdef __LP64__
 call boot_setup_tls
 call boot_setup_long_mode
 pushl $BOOT_GDT_SEL_CODE64
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
 ljmp $BOOT_GDT_SEL_CODE, $1f

1:
#endif /* __LP64__ */

 call cpu_get_boot_stack

#ifdef __LP64__
 movq %rax, %rsp
 addq $BOOT_STACK_SIZE, %rsp
#else /* __LP64__ */
 movl %eax, %esp
 addl $BOOT_STACK_SIZE, %esp
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
 ljmp $BOOT_GDT_SEL_CODE, $BOOT_MP_ADDR_PTOT(1f)

.align 4
1:
 .code32
 movl $BOOT_GDT_SEL_DATA, %eax
 movl %eax, %ds
 movl %eax, %es
 movl %eax, %ss
 xorl %eax, %eax
 movl %eax, %fs
 movl %eax, %gs
 ljmp $BOOT_GDT_SEL_CODE, $boot_ap_start32
ASM_END(boot_mp_trampoline)

ASM_DATA(boot_ap_gdtr)
 .word boot_gdt_end - boot_gdt - 1
 .long BOOT_MP_ADDR_PTOT(boot_gdt)
ASM_END(boot_ap_gdtr)

ASM_DATA(boot_gdt)
 .quad 0x0000000000000000   /* Null descriptor */
 .quad 0x00cf9a000000ffff   /* Code segment descriptor */
 .quad 0x00cf92000000ffff   /* Data segment descriptor */
#ifdef __LP64__
 .quad 0x00209a0000000000   /* 64-bit code segment selector */
#else /* __LP64__ */
 .quad 0x0                  /* TLS segment descriptor, filled at boot time */
#endif /* __LP64__ */
ASM_END(boot_gdt)
boot_gdt_end:

ASM_DATA(boot_mp_trampoline_size)
 .long . - boot_mp_trampoline
ASM_END(boot_mp_trampoline_size)
