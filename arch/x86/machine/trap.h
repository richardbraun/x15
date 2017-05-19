/*
 * Copyright (c) 2011-2014 Richard Braun.
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
 *
 *
 * Trap (interrupt and exception) handling.
 */

#ifndef _X86_TRAP_H
#define _X86_TRAP_H

/*
 * Architecture defined traps.
 */
#define TRAP_DE             0   /* Divide Error */
#define TRAP_DB             1   /* Debug */
#define TRAP_NMI            2   /* NMI Interrupt */
#define TRAP_BP             3   /* Breakpoint */
#define TRAP_OF             4   /* Overflow */
#define TRAP_BR             5   /* BOUND Range Exceeded */
#define TRAP_UD             6   /* Invalid Opcode (Undefined Opcode) */
#define TRAP_NM             7   /* Device Not Available (No Math Coprocessor) */
#define TRAP_DF             8   /* Double Fault */
#define TRAP_TS             10  /* Invalid TSS */
#define TRAP_NP             11  /* Segment Not Present */
#define TRAP_SS             12  /* Stack-Segment Fault */
#define TRAP_GP             13  /* General Protection */
#define TRAP_PF             14  /* Page Fault */
#define TRAP_MF             16  /* x87 FPU Floating-Point Error (Math Fault) */
#define TRAP_AC             17  /* Alignment Check */
#define TRAP_MC             18  /* Machine Check */
#define TRAP_XM             19  /* SIMD Floating-Point Exception */

/*
 * Interrupts reserved for the legacy PIC.
 */
#define TRAP_PIC_BASE       32

/*
 * System defined traps.
 *
 * The local APIC assigns one priority every 16 vectors.
 */
#define TRAP_XCALL              238
#define TRAP_THREAD_SCHEDULE    239
#define TRAP_CPU_HALT           240
#define TRAP_LAPIC_TIMER        253
#define TRAP_LAPIC_ERROR        254
#define TRAP_LAPIC_SPURIOUS     255

/*
 * Vector identifying an unhandled trap.
 */
#define TRAP_DEFAULT        256

#ifndef __ASSEMBLER__

#include <stdint.h>
#include <stdio.h>

#include <kern/macros.h>

#ifdef __LP64__

struct trap_frame {
    uint64_t rax;
    uint64_t rbx;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rbp;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t vector;
    uint64_t error;
    uint64_t rip;
    uint64_t cs;
    uint64_t rflags;
    uint64_t rsp;
    uint64_t ss;
} __packed;

#else /* __LP64__ */

struct trap_frame {
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
    uint32_t ebp;
    uint32_t esi;
    uint32_t edi;
    uint16_t ds;
    uint16_t es;
    uint16_t fs;
    uint16_t gs;
    uint32_t vector;
    uint32_t error;
    uint32_t eip;
    uint32_t cs;
    uint32_t eflags;
    uint32_t esp;       /* esp and ss are undefined if trapped in kernel */
    uint32_t ss;
} __packed;

#endif /* __LP64__ */

static inline void
trap_test_double_fault(void)
{
    printf("trap: double fault test\n");
    asm volatile("movl $0xdead, %esp; push $0");
}

/*
 * Set up the trap module.
 */
void trap_setup(void);

/*
 * Unified trap entry point.
 */
void trap_main(struct trap_frame *frame);

/*
 * Display the content of a trap frame.
 */
void trap_frame_show(struct trap_frame *frame);

/*
 * Display the call trace interrupted by the trap of the given frame.
 */
void trap_stack_show(struct trap_frame *frame);

/*
 * Return a pointer to the local interrupt stack.
 *
 * This function is called by the low level trap handling code.
 *
 * Return NULL if no stack switching is required.
 */
void * trap_get_interrupt_stack(const struct trap_frame *frame);

#endif /* __ASSEMBLER__ */

#endif /* _X86_TRAP_H */
