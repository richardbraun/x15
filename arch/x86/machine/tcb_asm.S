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
 movq (%rdi), %rbp      /* load frame pointer from TCB */
 movq 8(%rdi), %rsp     /* load stack pointer from TCB */
 movq 16(%rdi), %rax    /* load instruction pointer from TCB */
 pushq $CPU_EFL_ONE     /* prepare new RFLAGS register value */
 popfq                  /* load value into RFLAGS register */
 jmp *%rax              /* branch to loaded instruction pointer */
ASM_END(tcb_context_load)

#else /* __LP64__ */

ASM_ENTRY(tcb_context_load)
 movl 4(%esp), %eax     /* load TCB address */
 movl (%eax), %ebp      /* load frame pointer from TCB */
 movl 4(%eax), %esp     /* load stack pointer from TCB */
 movl 8(%eax), %ecx     /* load instruction pointer from TCB */
 pushl $CPU_EFL_ONE     /* prepare new EFLAGS register value */
 popfl                  /* load value into EFLAGS register */
 jmp *%ecx              /* branch to loaded instruction pointer */
ASM_END(tcb_context_load)

#endif /* __LP64__ */

.text

#ifdef __LP64__

ASM_ENTRY(tcb_start)
 popq %rax              /* load function passed at TCB initialization (this
                           makes the stack pointer reach the stack top) */
 call *%rax             /* branch to loaded function, pushing the return
                           address to start a clean stack trace */

 /* Never reached */
 nop                    /* Make the return address point to an instruction
                           inside the function to build a clean stack trace */
ASM_END(tcb_start)

ASM_ENTRY(tcb_context_switch)
 pushfq                 /* store registers as required by ABI */
 pushq %rbx
 pushq %r12
 pushq %r13
 pushq %r14
 pushq %r15
 movq %rbp, (%rdi)      /* store frame pointer into prev TCB */
 movq %rsp, 8(%rdi)     /* store stack pointer into prev TCB */
 movq $1f, 16(%rdi)     /* store next instruction address into prev TCB */
 movq (%rsi), %rbp      /* load frame pointer from next TCB */
 movq 8(%rsi), %rsp     /* load stack pointer from next TCB */
 movq 16(%rsi), %rax    /* load instruction pointer from next TCB */
 jmp *%rax              /* branch to loaded instruction pointer */

/*
 * This code is run on context restoration. The frame and stack pointers
 * have already been loaded to their correct values. Load registers which
 * were stored on the stack when the context was saved and return.
 */
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
 popl %eax              /* load function passed at TCB initialization (this
                           makes the stack pointer reach the stack top) */
 call *%eax             /* branch to loaded function, pushing the return
                           address to start a clean stack trace */

 /* Never reached */
 nop                    /* Make the return address point to an instruction
                           inside the function to build a clean stack trace */
ASM_END(tcb_start)

ASM_ENTRY(tcb_context_switch)
 movl 4(%esp), %eax     /* load prev TCB address */
 movl 8(%esp), %ecx     /* load next TCB address */
 pushfl                 /* store registers as required by ABI */
 pushl %ebx
 pushl %edi
 pushl %esi
 movl %ebp, (%eax)      /* store frame pointer into prev TCB */
 movl %esp, 4(%eax)     /* store stack pointer into prev TCB */
 movl $1f, 8(%eax)      /* store next instruction address into prev TCB */
 movl (%ecx), %ebp      /* load frame pointer from next TCB */
 movl 4(%ecx), %esp     /* load stack pointer from next TCB */
 movl 8(%ecx), %edx     /* load instruction pointer from next TCB */
 jmp *%edx              /* branch to loaded instruction pointer */

/*
 * This code is run on context restoration. The frame and stack pointers
 * have already been loaded to their correct values. Load registers which
 * were stored on the stack when the context was saved and return.
 */
1:
 popl %esi
 popl %edi
 popl %ebx
 popfl
 ret
ASM_END(tcb_context_switch)

#endif /* __LP64__ */
