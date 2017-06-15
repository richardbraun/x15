/*
 * Copyright (c) 2012-2017 Richard Braun.
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
 movq (%rdi), %rbp          /* load frame pointer from TCB */
 movq 8(%rdi), %rsp         /* load stack pointer from TCB */
 jmp tcb_context_restore
ASM_END(tcb_context_load)

#else /* __LP64__ */

ASM_ENTRY(tcb_context_load)
 movl 4(%esp), %eax         /* load TCB address */
 movl (%eax), %ebp          /* load frame pointer from TCB */
 movl 4(%eax), %esp         /* load stack pointer from TCB */
 jmp tcb_context_restore
ASM_END(tcb_context_load)

#endif /* __LP64__ */

.text

#ifdef __LP64__

ASM_ENTRY(tcb_start)
 popq %rdi              /* load function */
 popq %rsi              /* load argument */

 /*
  * Use the call instruction to start a clean stack trace.
  *
  * Note that, on amd64, the stack must be 16-byte before the call
  * instruction, so that "$(rsp + 8) is a multiple is always a multiple
  * of 16 when control is transferred to the function entry point",
  * which is another reason to use call instead of a bare jump.
  */
 call thread_main

 /* Never reached */
 nop                    /* make the return address point to an instruction
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
 movq (%rsi), %rbp      /* load frame pointer from next TCB */
 movq 8(%rsi), %rsp     /* load stack pointer from next TCB */

.global tcb_context_restore
tcb_context_restore:
 popq %r15              /* load registers as required by ABI */
 popq %r14
 popq %r13
 popq %r12
 popq %rbx
 popfq
 ret
ASM_END(tcb_context_switch)

#else /* __LP64__ */

ASM_ENTRY(tcb_start)
 call thread_main       /* the stack already contains the expected arguments
                           in the expected order, use the call instruction to
                           start a clean stack trace */

 /* Never reached */
 nop                    /* make the return address point to an instruction
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
 movl (%ecx), %ebp      /* load frame pointer from next TCB */
 movl 4(%ecx), %esp     /* load stack pointer from next TCB */

/*
 * This code is run on context restoration. The frame and stack pointers
 * have already been loaded to their correct values. Load registers which
 * were stored on the stack when the context was saved and return.
 */
.global tcb_context_restore
tcb_context_restore:
 popl %esi
 popl %edi
 popl %ebx
 popfl
 ret
ASM_END(tcb_context_switch)

#endif /* __LP64__ */
