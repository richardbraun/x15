/*
 * Copyright (c) 2012-2014 Richard Braun.
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
#include <machine/trap.h>

.text

#ifdef __LP64__

.macro TRAP_STORE_REGISTERS
 pushq %r15
 pushq %r14
 pushq %r13
 pushq %r12
 pushq %r11
 pushq %r10
 pushq %r9
 pushq %r8
 pushq %rdi
 pushq %rsi
 pushq %rbp
 pushq %rdx
 pushq %rcx
 pushq %rbx
 pushq %rax
.endm

.macro TRAP_LOAD_REGISTERS
 popq %rax
 popq %rbx
 popq %rcx
 popq %rdx
 popq %rbp
 popq %rsi
 popq %rdi
 popq %r8
 popq %r9
 popq %r10
 popq %r11
 popq %r12
 popq %r13
 popq %r14
 popq %r15
 addq $16, %rsp /* skip vector and error */
.endm

#define TRAP(vector, name)  \
ASM_ENTRY(name)             \
 pushq $0;                  \
 pushq $(vector);           \
 jmp trap_common;           \
ASM_END(name)

#define TRAP_ERROR(vector, name)    \
ASM_ENTRY(name)                     \
 pushq $(vector);                   \
 jmp trap_common;                   \
ASM_END(name)

ASM_ENTRY(trap_common)
 TRAP_STORE_REGISTERS
 movq %rsp, %rbx        /* save frame */
 movq %rbx, %rdi
 call trap_get_interrupt_stack
 testq %rax, %rax       /* switch stack ? */
 jz 1f
 movq %rax, %rsp        /* switch to interrupt stack TODO conditional move ? */
1:
 xorq %rbp, %rbp        /* block stack tracing */
 movq %rbx, %rdi
 call trap_main
 movq %rbx, %rsp        /* restore stack */
 call thread_schedule   /* schedule threads */
 TRAP_LOAD_REGISTERS
 iretq
ASM_END(trap_common)

#else /* __LP64__ */

.macro TRAP_STORE_REGISTERS
 pushw %gs
 pushw %fs
 pushw %es
 pushw %ds
 pushl %edi
 pushl %esi
 pushl %ebp
 pushl %edx
 pushl %ecx
 pushl %ebx
 pushl %eax
.endm

/* XXX Don't load segment registers for now */
.macro TRAP_LOAD_REGISTERS
 popl %eax
 popl %ebx
 popl %ecx
 popl %edx
 popl %ebp
 popl %esi
 popl %edi
 addl $16, %esp /* skip segment registers, vector and error */
.endm

#define TRAP(vector, name)  \
ASM_ENTRY(name)             \
 pushl $0;                  \
 pushl $(vector);           \
 jmp trap_common;           \
ASM_END(name)

#define TRAP_ERROR(vector, name)    \
ASM_ENTRY(name)                     \
 pushl $(vector);                   \
 jmp trap_common;                   \
ASM_END(name)

ASM_ENTRY(trap_common)
 TRAP_STORE_REGISTERS
 movl %esp, %ebx        /* save frame */
 pushl %ebx
 call trap_get_interrupt_stack
 addl $4, %esp
 testl %eax, %eax       /* switch stack ? */
 jz 1f
 movl %eax, %esp        /* switch to interrupt stack */
1:
 xorl %ebp, %ebp        /* block stack tracing */
 pushl %ebx
 call trap_main
 movl %ebx, %esp        /* restore stack */
 call thread_schedule   /* schedule threads */
 TRAP_LOAD_REGISTERS
 iret
ASM_END(trap_common)

#endif /* __LP64__ */

/* Architecture defined traps */
TRAP(TRAP_DE, trap_isr_divide_error)
TRAP(TRAP_DB, trap_isr_debug)
TRAP(TRAP_NMI, trap_isr_nmi)
TRAP(TRAP_BP, trap_isr_breakpoint)
TRAP(TRAP_OF, trap_isr_overflow)
TRAP(TRAP_BR, trap_isr_bound_range)
TRAP(TRAP_UD, trap_isr_invalid_opcode)
TRAP(TRAP_NM, trap_isr_device_not_available)
TRAP_ERROR(TRAP_DF, trap_isr_double_fault)
TRAP_ERROR(TRAP_TS, trap_isr_invalid_tss)
TRAP_ERROR(TRAP_NP, trap_isr_segment_not_present)
TRAP_ERROR(TRAP_SS, trap_isr_stack_segment_fault)
TRAP_ERROR(TRAP_GP, trap_isr_general_protection)
TRAP_ERROR(TRAP_PF, trap_isr_page_fault)
TRAP(TRAP_MF, trap_isr_math_fault)
TRAP_ERROR(TRAP_AC, trap_isr_alignment_check)
TRAP(TRAP_MC, trap_isr_machine_check)
TRAP(TRAP_XM, trap_isr_simd_fp_exception)

/* Basic PIC support */
TRAP(TRAP_PIC_BASE + 7, trap_isr_pic_int7)
TRAP(TRAP_PIC_BASE + 15, trap_isr_pic_int15)

/* System defined traps */
TRAP(TRAP_XCALL, trap_isr_xcall)
TRAP(TRAP_THREAD_SCHEDULE, trap_isr_thread_schedule)
TRAP(TRAP_CPU_HALT, trap_isr_cpu_halt)
TRAP(TRAP_LAPIC_TIMER, trap_isr_lapic_timer)
TRAP(TRAP_LAPIC_ERROR, trap_isr_lapic_error)
TRAP(TRAP_LAPIC_SPURIOUS, trap_isr_lapic_spurious)

/* Unhandled traps */
TRAP(TRAP_DEFAULT, trap_isr_default)
