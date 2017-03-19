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
 *
 *
 * XXX Many traps have not been tested. Some, such as NMIs, are known to need
 * additional configuration and resources to be properly handled.
 */

#include <kern/assert.h>
#include <kern/init.h>
#include <kern/macros.h>
#include <kern/param.h>
#include <kern/printk.h>
#include <kern/thread.h>
#include <machine/cpu.h>
#include <machine/lapic.h>
#include <machine/pic.h>
#include <machine/pmap.h>
#include <machine/strace.h>
#include <machine/trap.h>

/*
 * Type for interrupt service routines and trap handler functions.
 */
typedef void (*trap_isr_fn_t)(void);
typedef void (*trap_handler_fn_t)(struct trap_frame *);

/*
 * Trap handler flags.
 */
#define TRAP_HF_INTR 0x1    /* Enter interrupt context */

/*
 * Properties of a trap handler.
 */
struct trap_handler {
    int flags;
    trap_handler_fn_t fn;
};

/*
 * Low level interrupt service routines.
 */
void trap_isr_default(void);
void trap_isr_divide_error(void);
void trap_isr_debug(void);
void trap_isr_nmi(void);
void trap_isr_breakpoint(void);
void trap_isr_overflow(void);
void trap_isr_bound_range(void);
void trap_isr_invalid_opcode(void);
void trap_isr_device_not_available(void);
void trap_isr_double_fault(void);
void trap_isr_invalid_tss(void);
void trap_isr_segment_not_present(void);
void trap_isr_stack_segment_fault(void);
void trap_isr_general_protection(void);
void trap_isr_page_fault(void);
void trap_isr_math_fault(void);
void trap_isr_alignment_check(void);
void trap_isr_machine_check(void);
void trap_isr_simd_fp_exception(void);
void trap_isr_pic_int7(void);
void trap_isr_pic_int15(void);
void trap_isr_xcall(void);
void trap_isr_thread_schedule(void);
void trap_isr_cpu_halt(void);
void trap_isr_lapic_timer(void);
void trap_isr_lapic_error(void);
void trap_isr_lapic_spurious(void);

/*
 * Array of trap handlers.
 *
 * The additional entry is the default entry used for unhandled traps.
 */
static struct trap_handler trap_handlers[CPU_IDT_SIZE + 1] __read_mostly;

static void __init
trap_handler_init(struct trap_handler *handler, int flags, trap_handler_fn_t fn)
{
    handler->flags = flags;
    handler->fn = fn;
}

static void __init
trap_install(unsigned int vector, int flags, trap_isr_fn_t isr,
             trap_handler_fn_t fn)
{
    assert(vector < CPU_IDT_SIZE);

    trap_handler_init(&trap_handlers[vector], flags, fn);
    cpu_idt_set_gate(vector, isr);
}

static void
trap_show_thread(void)
{
    struct thread *thread;

    thread = thread_self();
    printk("trap: interrupted thread: %p (%s)\n", thread, thread->name);
}

static void
trap_double_fault(struct trap_frame *frame)
{
    cpu_halt_broadcast();

#ifndef __LP64__
    struct trap_frame frame_store;
    struct cpu *cpu;

    /*
     * Double faults are catched through a task gate, which makes the given
     * frame useless. The interrupted state is automatically saved in the
     * main TSS by the processor. Build a proper trap frame from there.
     */
    frame = &frame_store;
    cpu = cpu_current();
    frame->eax = cpu->tss.eax;
    frame->ebx = cpu->tss.ebx;
    frame->ecx = cpu->tss.ecx;
    frame->edx = cpu->tss.edx;
    frame->ebp = cpu->tss.ebp;
    frame->esi = cpu->tss.esi;
    frame->edi = cpu->tss.edi;
    frame->ds = cpu->tss.ds;
    frame->es = cpu->tss.es;
    frame->fs = cpu->tss.fs;
    frame->gs = cpu->tss.gs;
    frame->vector = TRAP_DF;
    frame->error = 0;
    frame->eip = cpu->tss.eip;
    frame->cs = cpu->tss.cs;
    frame->eflags = cpu->tss.eflags;
    frame->esp = cpu->tss.esp;
    frame->ss = cpu->tss.ss;
#endif /* __LP64__ */

    printk("trap: double fault (cpu%u):\n", cpu_id());
    trap_show_thread();
    trap_frame_show(frame);
    trap_stack_show(frame);
    cpu_halt();
}

static void __init
trap_install_double_fault(void)
{
    trap_handler_init(&trap_handlers[TRAP_DF], TRAP_HF_INTR, trap_double_fault);
    cpu_idt_set_double_fault(trap_isr_double_fault);
}

static void
trap_default(struct trap_frame *frame)
{
    cpu_halt_broadcast();
    printk("trap: unhandled interrupt or exception (cpu%u):\n", cpu_id());
    trap_show_thread();
    trap_frame_show(frame);
    trap_stack_show(frame);
    cpu_halt();
}

void __init
trap_setup(void)
{
    size_t i;

    for (i = 0; i < CPU_IDT_SIZE; i++) {
        trap_install(i, TRAP_HF_INTR, trap_isr_default, trap_default);
    }

    /* Architecture defined traps */
    trap_install(TRAP_DE, 0, trap_isr_divide_error, trap_default);
    trap_install(TRAP_DB, 0, trap_isr_debug, trap_default);
    trap_install(TRAP_NMI, TRAP_HF_INTR, trap_isr_nmi, trap_default);
    trap_install(TRAP_BP, 0, trap_isr_breakpoint, trap_default);
    trap_install(TRAP_OF, 0, trap_isr_overflow, trap_default);
    trap_install(TRAP_BR, 0, trap_isr_bound_range, trap_default);
    trap_install(TRAP_UD, 0, trap_isr_invalid_opcode, trap_default);
    trap_install(TRAP_NM, 0, trap_isr_device_not_available, trap_default);
    trap_install_double_fault();
    trap_install(TRAP_TS, 0, trap_isr_invalid_tss, trap_default);
    trap_install(TRAP_NP, 0, trap_isr_segment_not_present, trap_default);
    trap_install(TRAP_SS, 0, trap_isr_stack_segment_fault, trap_default);
    trap_install(TRAP_GP, 0, trap_isr_general_protection, trap_default);
    trap_install(TRAP_PF, 0, trap_isr_page_fault, trap_default);
    trap_install(TRAP_MF, 0, trap_isr_math_fault, trap_default);
    trap_install(TRAP_AC, 0, trap_isr_alignment_check, trap_default);
    trap_install(TRAP_MC, TRAP_HF_INTR, trap_isr_machine_check, trap_default);
    trap_install(TRAP_XM, 0, trap_isr_simd_fp_exception, trap_default);

    /* Basic PIC support */
    trap_install(TRAP_PIC_BASE + 7, TRAP_HF_INTR,
                 trap_isr_pic_int7, pic_spurious_intr);
    trap_install(TRAP_PIC_BASE + 15, TRAP_HF_INTR,
                 trap_isr_pic_int15, pic_spurious_intr);

    /* System defined traps */
    trap_install(TRAP_XCALL, TRAP_HF_INTR,
                 trap_isr_xcall, cpu_xcall_intr);
    trap_install(TRAP_THREAD_SCHEDULE, TRAP_HF_INTR,
                 trap_isr_thread_schedule, cpu_thread_schedule_intr);
    trap_install(TRAP_CPU_HALT, TRAP_HF_INTR,
                 trap_isr_cpu_halt, cpu_halt_intr);
    trap_install(TRAP_LAPIC_TIMER, TRAP_HF_INTR,
                 trap_isr_lapic_timer, lapic_timer_intr);
    trap_install(TRAP_LAPIC_ERROR, TRAP_HF_INTR,
                 trap_isr_lapic_error, lapic_error_intr);
    trap_install(TRAP_LAPIC_SPURIOUS, TRAP_HF_INTR,
                 trap_isr_lapic_spurious, lapic_spurious_intr);

    trap_handler_init(&trap_handlers[TRAP_DEFAULT], TRAP_HF_INTR, trap_default);
}

void
trap_main(struct trap_frame *frame)
{
    struct trap_handler *handler;

    assert(frame->vector < ARRAY_SIZE(trap_handlers));

    handler = &trap_handlers[frame->vector];

    if (handler->flags & TRAP_HF_INTR) {
        thread_intr_enter();
    }

    handler->fn(frame);

    if (handler->flags & TRAP_HF_INTR) {
        thread_intr_leave();
    }

    thread_schedule();
}

#ifdef __LP64__

void
trap_frame_show(struct trap_frame *frame)
{
    printk("trap: rax: %016lx rbx: %016lx rcx: %016lx\n"
           "trap: rdx: %016lx rbp: %016lx rsi: %016lx\n"
           "trap: rdi: %016lx  r8: %016lx  r9: %016lx\n"
           "trap: r10: %016lx r11: %016lx r12: %016lx\n"
           "trap: r13: %016lx r14: %016lx r15: %016lx\n"
           "trap: vector: %lu error: %08lx\n"
           "trap: rip: %016lx cs: %lu rflags: %016lx\n"
           "trap: rsp: %016lx ss: %lu\n",
           (unsigned long)frame->rax, (unsigned long)frame->rbx,
           (unsigned long)frame->rcx, (unsigned long)frame->rdx,
           (unsigned long)frame->rbp, (unsigned long)frame->rsi,
           (unsigned long)frame->rdi, (unsigned long)frame->r8,
           (unsigned long)frame->r9, (unsigned long)frame->r10,
           (unsigned long)frame->r11, (unsigned long)frame->r12,
           (unsigned long)frame->r13, (unsigned long)frame->r14,
           (unsigned long)frame->r15, (unsigned long)frame->vector,
           (unsigned long)frame->error, (unsigned long)frame->rip,
           (unsigned long)frame->cs, (unsigned long)frame->rflags,
           (unsigned long)frame->rsp, (unsigned long)frame->ss);

    /* XXX Until the page fault handler is written */
    if (frame->vector == 14) {
        printk("trap: cr2: %016lx\n", (unsigned long)cpu_get_cr2());
    }
}

#else /* __LP64__ */

void
trap_frame_show(struct trap_frame *frame)
{
    unsigned long esp, ss;

    if ((frame->cs & CPU_PL_USER) || (frame->vector == TRAP_DF)) {
        esp = frame->esp;
        ss = frame->ss;
    } else {
        esp = 0;
        ss = 0;
    }

    printk("trap: eax: %08lx ebx: %08lx ecx: %08lx edx: %08lx\n"
           "trap: ebp: %08lx esi: %08lx edi: %08lx\n"
           "trap: ds: %hu es: %hu fs: %hu gs: %hu\n"
           "trap: vector: %lu error: %08lx\n"
           "trap: eip: %08lx cs: %lu eflags: %08lx\n"
           "trap: esp: %08lx ss: %lu\n",
           (unsigned long)frame->eax, (unsigned long)frame->ebx,
           (unsigned long)frame->ecx, (unsigned long)frame->edx,
           (unsigned long)frame->ebp, (unsigned long)frame->esi,
           (unsigned long)frame->edi, (unsigned short)frame->ds,
           (unsigned short)frame->es, (unsigned short)frame->fs,
           (unsigned short)frame->gs, (unsigned long)frame->vector,
           (unsigned long)frame->error, (unsigned long)frame->eip,
           (unsigned long)frame->cs, (unsigned long)frame->eflags,
           (unsigned long)esp, (unsigned long)ss);


    /* XXX Until the page fault handler is written */
    if (frame->vector == 14) {
        printk("trap: cr2: %08lx\n", (unsigned long)cpu_get_cr2());
    }
}

#endif /* __LP64__ */

void
trap_stack_show(struct trap_frame *frame)
{
#ifdef __LP64__
    strace_show(frame->rip, frame->rbp);
#else /* __LP64__ */
    strace_show(frame->eip, frame->ebp);
#endif /* __LP64__ */
}
