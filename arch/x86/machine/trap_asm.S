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

#ifdef __LP64__

#define TRAP_PUSH_REGISTERS         \
 pushq %r15;                        \
 pushq %r14;                        \
 pushq %r13;                        \
 pushq %r12;                        \
 pushq %r11;                        \
 pushq %r10;                        \
 pushq %r9;                         \
 pushq %r8;                         \
 pushq %rdi;                        \
 pushq %rsi;                        \
 pushq %rbp;                        \
 pushq %rdx;                        \
 pushq %rcx;                        \
 pushq %rbx;                        \
 pushq %rax

#define TRAP_POP_REGISTERS          \
 popq %rax;                         \
 popq %rbx;                         \
 popq %rcx;                         \
 popq %rdx;                         \
 popq %rbp;                         \
 popq %rsi;                         \
 popq %rdi;                         \
 popq %r8;                          \
 popq %r9;                          \
 popq %r10;                         \
 popq %r11;                         \
 popq %r12;                         \
 popq %r13;                         \
 popq %r14;                         \
 popq %r15

#define TRAP(vector, name)          \
ASM_ENTRY(trap_isr_ ## name)        \
 pushq $0;                          \
 pushq $vector;                     \
 TRAP_PUSH_REGISTERS;               \
 movq %rsp, %rdi;                   \
 call trap_main;                    \
 TRAP_POP_REGISTERS;                \
 addq $16, %rsp;                    \
 iretq;                             \
ASM_END(trap_isr_ ## name)

#define TRAP_ERROR(vector, name)    \
ASM_ENTRY(trap_isr_ ## name)        \
 pushq $vector;                     \
 TRAP_PUSH_REGISTERS;               \
 movq %rsp, %rdi;                   \
 call trap_main;                    \
 TRAP_POP_REGISTERS;                \
 addq $16, %rsp;                    \
 iretq;                             \
ASM_END(trap_isr_ ## name)

#else /* __LP64__ */

#define TRAP_PUSH_REGISTERS         \
 pushl %gs;                         \
 pushl %fs;                         \
 pushl %es;                         \
 pushl %ds;                         \
 pushl %edi;                        \
 pushl %esi;                        \
 pushl %ebp;                        \
 pushl %edx;                        \
 pushl %ecx;                        \
 pushl %ebx;                        \
 pushl %eax

#define TRAP_POP_REGISTERS          \
 popl %eax;                         \
 popl %ebx;                         \
 popl %ecx;                         \
 popl %edx;                         \
 popl %ebp;                         \
 popl %esi;                         \
 popl %edi;                         \
 popl %ds;                          \
 popl %es;                          \
 popl %fs;                          \
 popl %gs;                          \

#define TRAP(vector, name)          \
ASM_ENTRY(trap_isr_ ## name)        \
 pushl $0;                          \
 pushl $vector;                     \
 TRAP_PUSH_REGISTERS;               \
 pushl %esp;                        \
 call trap_main;                    \
 addl $4, %esp;                     \
 TRAP_POP_REGISTERS;                \
 addl $8, %esp;                     \
 iret;                              \
ASM_END(trap_isr_ ## name)

#define TRAP_ERROR(vector, name)    \
ASM_ENTRY(trap_isr_ ## name)        \
 pushl $vector;                     \
 TRAP_PUSH_REGISTERS;               \
 pushl %esp;                        \
 call trap_main;                    \
 addl $4, %esp;                     \
 TRAP_POP_REGISTERS;                \
 addl $8, %esp;                     \
 iret;                              \
ASM_END(trap_isr_ ## name)

#endif /* __LP64__ */

.text

TRAP(-1, default)

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

/* System defined traps */
TRAP(TRAP_LAPIC_TIMER, lapic_timer)
TRAP(TRAP_LAPIC_ERROR, lapic_error)
TRAP(TRAP_LAPIC_SPURIOUS, lapic_spurious)
