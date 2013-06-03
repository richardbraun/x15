/*
 * Copyright (c) 2012, 2013 Richard Braun.
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
 movq (%rdi), %rbp
 movq 8(%rdi), %rsp
 movq 16(%rdi), %rax
 pushq $CPU_EFL_ONE
 popfq
 jmp *%rax
ASM_END(tcb_context_load)

#else /* __LP64__ */

ASM_ENTRY(tcb_context_load)
 movl 4(%esp), %eax
 movl (%eax), %ebp
 movl 4(%eax), %esp
 movl 8(%eax), %ecx
 pushl $CPU_EFL_ONE
 popfl
 jmp *%ecx
ASM_END(tcb_context_load)

#endif /* __LP64__ */

.text

#ifdef __LP64__

ASM_ENTRY(tcb_start)
 popq %rax
 call *%rax

 /* Never reached */
 nop
ASM_END(tcb_start)

ASM_ENTRY(tcb_context_switch)
 pushfq
 pushq %rbx
 pushq %r12
 pushq %r13
 pushq %r14
 pushq %r15
 movq %rbp, (%rdi)
 movq %rsp, 8(%rdi)
 movq $1f, 16(%rdi)
 movq (%rsi), %rbp
 movq 8(%rsi), %rsp
 movq 16(%rsi), %rax
 jmp *%rax

1:
 popq %r15
 popq %r14
 popq %r13
 popq %r12
 popq %rbx
 popfq
 ret
ASM_END(tcb_context_switch)

#else /* __LP64__ */

ASM_ENTRY(tcb_start)
 popl %eax
 call *%eax

 /* Never reached */
 nop
ASM_END(tcb_start)

ASM_ENTRY(tcb_context_switch)
 movl 4(%esp), %eax
 movl 8(%esp), %ecx
 pushfl
 pushl %ebx
 pushl %edi
 pushl %esi
 movl %ebp, (%eax)
 movl %esp, 4(%eax)
 movl $1f, 8(%eax)
 movl (%ecx), %ebp
 movl 4(%ecx), %esp
 movl 8(%ecx), %edx
 jmp *%edx

1:
 popl %esi
 popl %edi
 popl %ebx
 popfl
 ret
ASM_END(tcb_context_switch)

#endif /* __LP64__ */
