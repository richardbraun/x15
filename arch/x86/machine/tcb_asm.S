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

#include <kern/init.h>
#include <machine/asm.h>
#include <machine/cpu.h>

.section INIT_SECTION

#ifdef __LP64__

ASM_ENTRY(tcb_context_load)
 movq 8(%rdi), %rax
 movq (%rdi), %rsp
 pushq $CPU_EFL_ONE
 popfq
 jmp *%rax
ASM_END(tcb_context_load)

#else /* __LP64__ */

ASM_ENTRY(tcb_context_load)
 movl 4(%esp), %eax
 movl 4(%eax), %ecx
 movl (%eax), %esp
 pushl $CPU_EFL_ONE
 popfl
 jmp *%ecx
ASM_END(tcb_context_load)

#endif /* __LP64__ */

.text

#ifdef __LP64__

ASM_ENTRY(tcb_start)
 popq %rax
 xorq %rbp, %rbp
 call *%rax

 /* Never reached */
 nop
ASM_END(tcb_start)

ASM_ENTRY(tcb_context_switch)
 pushfq
 pushq %rbx
 pushq %rbp
 pushq %r12
 pushq %r13
 pushq %r14
 pushq %r15
 movq %rsp, (%rdi)
 movq $1f, 8(%rdi)
 movq (%rsi), %rsp
 movq 8(%rsi), %rax
 jmp *%rax

1:
 popq %r15
 popq %r14
 popq %r13
 popq %r12
 popq %rbp
 popq %rbx
 popfq
 ret
ASM_END(tcb_context_switch)

#else /* __LP64__ */

ASM_ENTRY(tcb_start)
 popl %eax
 xorl %ebp, %ebp
 call *%eax

 /* Never reached */
 nop
ASM_END(tcb_start)

ASM_ENTRY(tcb_context_switch)
 movl 4(%esp), %eax
 movl 8(%esp), %ecx
 pushfl
 pushl %ebx
 pushl %ebp
 pushl %edi
 pushl %esi
 movl %esp, (%eax)
 movl $1f, 4(%eax)
 movl (%ecx), %esp
 movl 4(%ecx), %edx
 jmp *%edx

1:
 popl %esi
 popl %edi
 popl %ebp
 popl %ebx
 popfl
 ret
ASM_END(tcb_context_switch)

#endif /* __LP64__ */
