/*
 * Copyright (c) 2012 Richard Braun.
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

#define TRAP(vector, name)          \
ASM_ENTRY(trap_isr_ ## name)        \
 pushq $0;                          \
 pushq $(vector);                   \
 jmp trap_common;                   \
ASM_END(trap_isr_ ## name)

#define TRAP_ERROR(vector, name)    \
ASM_ENTRY(trap_isr_ ## name)        \
 pushq $(vector);                   \
 jmp trap_common;                   \
ASM_END(trap_isr_ ## name)

ASM_ENTRY(trap_common)
 TRAP_STORE_REGISTERS
 movq %rsp, %rdi
 call trap_main
 TRAP_LOAD_REGISTERS
 iretq
ASM_END(trap_common)

#else /* __LP64__ */

.macro TRAP_STORE_REGISTERS
 pushl %gs
 pushl %fs
 pushl %es
 pushl %ds
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
 addl $24, %esp /* skip segment registers, vector and error */
.endm

#define TRAP(vector, name)          \
ASM_ENTRY(trap_isr_ ## name)        \
 pushl $0;                          \
 pushl $(vector);                   \
 jmp trap_common;                   \
ASM_END(trap_isr_ ## name)

#define TRAP_ERROR(vector, name)    \
ASM_ENTRY(trap_isr_ ## name)        \
 pushl $(vector);                   \
 jmp trap_common;                   \
ASM_END(trap_isr_ ## name)

ASM_ENTRY(trap_common)
 TRAP_STORE_REGISTERS
 pushl %esp
 call trap_main
 addl $4, %esp
 TRAP_LOAD_REGISTERS
 iret
ASM_END(trap_common)

#endif /* __LP64__ */

/* Architecture defined traps */
TRAP(TRAP_DE, divide_error)
TRAP(TRAP_DB, debug)
TRAP(TRAP_NMI, nmi)
TRAP(TRAP_BP, breakpoint)
TRAP(TRAP_OF, overflow)
TRAP(TRAP_BR, bound_range)
TRAP(TRAP_UD, invalid_opcode)
TRAP(TRAP_NM, device_not_available)
TRAP_ERROR(TRAP_DF, double_fault)
TRAP_ERROR(TRAP_TS, invalid_tss)
TRAP_ERROR(TRAP_NP, segment_not_present)
TRAP_ERROR(TRAP_SS, stack_segment_fault)
TRAP_ERROR(TRAP_GP, general_protection)
TRAP_ERROR(TRAP_PF, page_fault)
TRAP(TRAP_MF, math_fault)
TRAP_ERROR(TRAP_AC, alignment_check)
TRAP(TRAP_MC, machine_check)
TRAP(TRAP_XM, simd_fp_exception)

/* Basic PIC support */
TRAP(TRAP_PIC_BASE + 7, pic_int7)
TRAP(TRAP_PIC_BASE + 15, pic_int15)

/* System defined traps */
TRAP(TRAP_RESCHEDULE, reschedule)
TRAP(TRAP_PMAP_UPDATE, pmap_update)
TRAP(TRAP_CPU_HALT, cpu_halt)
TRAP(TRAP_LAPIC_TIMER, lapic_timer)
TRAP(TRAP_LAPIC_ERROR, lapic_error)
TRAP(TRAP_LAPIC_SPURIOUS, lapic_spurious)

/* Unhandled traps */
TRAP(TRAP_DEFAULT, default)
