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
#define TRAP_PMAP_UPDATE    240
#define TRAP_LAPIC_TIMER    253
#define TRAP_LAPIC_ERROR    254
#define TRAP_LAPIC_SPURIOUS 255

/*
 * Vector identifying an unhandled trap.
 */
#define TRAP_DEFAULT        256

#ifndef __ASSEMBLER__

#include <kern/macros.h>

#ifdef __LP64__

struct trap_frame {
    unsigned long rax;
    unsigned long rbx;
    unsigned long rcx;
    unsigned long rdx;
    unsigned long rbp;
    unsigned long rsi;
    unsigned long rdi;
    unsigned long r8;
    unsigned long r9;
    unsigned long r10;
    unsigned long r11;
    unsigned long r12;
    unsigned long r13;
    unsigned long r14;
    unsigned long r15;
    unsigned long vector;
    unsigned long error;
    unsigned long rip;
    unsigned long cs;
    unsigned long rflags;
    unsigned long rsp;
    unsigned long ss;
} __packed;

#else /* __LP64__ */

struct trap_frame {
    unsigned long eax;
    unsigned long ebx;
    unsigned long ecx;
    unsigned long edx;
    unsigned long ebp;
    unsigned long esi;
    unsigned long edi;
    unsigned long ds;
    unsigned long es;
    unsigned long fs;
    unsigned long gs;
    unsigned long vector;
    unsigned long error;
    unsigned long eip;
    unsigned long cs;
    unsigned long eflags;
    unsigned long esp;      /* esp and ss are undefined if trapped in kernel */
    unsigned long ss;
} __packed;

#endif /* __LP64__ */

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
 * Load a context saved in a trap frame.
 * 
 * The caller context is lost.
 */
void __noreturn trap_load(struct trap_frame *frame);

#endif /* __ASSEMBLER__ */

#endif /* _X86_TRAP_H */
