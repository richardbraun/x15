/*
 * Copyright (c) 2011, 2012 Richard Braun.
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

.text

ASM_ENTRY(cpu_load_gdt)
#ifdef __LP64__
 lgdt (%rsi)
#else /* __LP64__ */
 movl 8(%esp), %eax
 lgdt (%eax)
#endif /* __LP64__ */

 movl $CPU_GDT_SEL_DATA, %eax
 movl %eax, %ds
 movl %eax, %es
 movl %eax, %ss

#ifdef __LP64__
 movq %rdi, %rax
 movq %rdi, %rdx
 shrq $32, %rdx
 movq $CPU_MSR_FSBASE, %rcx
 wrmsr
#else /* __LP64__ */
 movl $CPU_GDT_SEL_CPU, %eax
 movl %eax, %fs
#endif /* __LP64__ */

 movl $CPU_GDT_SEL_NULL, %eax
 movl %eax, %gs

 /* Alter the stack to reload the code segment using a far return */
#ifdef __LP64__
 popq %rax
 pushq $CPU_GDT_SEL_CODE
 pushq %rax
 lretq
#else /* __LP64__ */
 popl %eax
 pushl $CPU_GDT_SEL_CODE
 pushl %eax
 lret
#endif /* __LP64__ */
ASM_END(cpu_load_gdt)
