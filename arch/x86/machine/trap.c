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

#include <stdint.h>
#include <stdio.h>

#include <kern/assert.h>
#include <kern/atomic.h>
#include <kern/init.h>
#include <kern/macros.h>
#include <kern/param.h>
#include <kern/spinlock.h>
#include <kern/thread.h>
#include <machine/cpu.h>
#include <machine/lapic.h>
#include <machine/pic.h>
#include <machine/pmap.h>
#include <machine/strace.h>
#include <machine/trap.h>

struct trap_cpu_data {
    unsigned char intr_stack[STACK_SIZE] __aligned(DATA_ALIGN);
};

static struct trap_cpu_data trap_cpu_data __percpu;

/*
 * Type for interrupt service routines and trap handler functions.
 */
typedef void (*trap_isr_fn_t)(void);

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
 * Table of ISR addresses.
 */
extern trap_isr_fn_t trap_isr_table[CPU_IDT_SIZE];

/*
 * Array of trap handlers.
 */
static struct trap_handler trap_handlers[CPU_IDT_SIZE] __read_mostly;

/*
 * Global trap lock.
 *
 * This lock is currently only used to serialize concurrent trap handler
 * updates.
 *
 * Interrupts must be disabled when holding this lock.
 */
static struct spinlock trap_lock;

static struct trap_handler *
trap_handler_get(unsigned int vector)
{
    assert(vector < ARRAY_SIZE(trap_handlers));
    return &trap_handlers[vector];
}

static void __init
trap_handler_init(struct trap_handler *handler, int flags, trap_handler_fn_t fn)
{
    handler->flags = flags;
    atomic_store(&handler->fn, fn, ATOMIC_RELAXED);
}

static void __init
trap_install(unsigned int vector, int flags, trap_handler_fn_t fn)
{
    assert(vector < ARRAY_SIZE(trap_handlers));
    trap_handler_init(trap_handler_get(vector), flags, fn);
}

static void
trap_show_thread(void)
{
    struct thread *thread;

    thread = thread_self();
    printf("trap: interrupted thread: %p (%s)\n", thread, thread->name);
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

    printf("trap: double fault (cpu%u):\n", cpu_id());
    trap_show_thread();
    trap_frame_show(frame);
    trap_stack_show(frame);
    cpu_halt();
}

static void __init
trap_install_double_fault(void)
{
    trap_install(TRAP_DF, TRAP_HF_INTR, trap_double_fault);
    cpu_idt_set_double_fault(trap_isr_table[TRAP_DF]);
}

static void
trap_default(struct trap_frame *frame)
{
    cpu_halt_broadcast();
    printf("trap: unhandled interrupt or exception (cpu%u):\n", cpu_id());
    trap_show_thread();
    trap_frame_show(frame);
    trap_stack_show(frame);
    cpu_halt();
}

void __init
trap_setup(void)
{
    size_t i;

    spinlock_init(&trap_lock);

    for (i = 0; i < ARRAY_SIZE(trap_isr_table); i++) {
        cpu_idt_set_gate(i, trap_isr_table[i]);
    }

    for (i = 0; i < ARRAY_SIZE(trap_handlers); i++) {
        trap_install(i, TRAP_HF_INTR, trap_default);
    }

    /* Architecture defined traps */
    trap_install(TRAP_DE, 0, trap_default);
    trap_install(TRAP_DB, 0, trap_default);
    trap_install(TRAP_NMI, TRAP_HF_INTR, trap_default);
    trap_install(TRAP_BP, 0, trap_default);
    trap_install(TRAP_OF, 0, trap_default);
    trap_install(TRAP_BR, 0, trap_default);
    trap_install(TRAP_UD, 0, trap_default);
    trap_install(TRAP_NM, 0, trap_default);
    trap_install_double_fault();
    trap_install(TRAP_TS, 0, trap_default);
    trap_install(TRAP_NP, 0, trap_default);
    trap_install(TRAP_SS, 0, trap_default);
    trap_install(TRAP_GP, 0, trap_default);
    trap_install(TRAP_PF, 0, trap_default);
    trap_install(TRAP_MF, 0, trap_default);
    trap_install(TRAP_AC, 0, trap_default);
    trap_install(TRAP_MC, TRAP_HF_INTR, trap_default);
    trap_install(TRAP_XM, 0, trap_default);

    /* System defined traps */
    trap_install(TRAP_XCALL, TRAP_HF_INTR, cpu_xcall_intr);
    trap_install(TRAP_THREAD_SCHEDULE, TRAP_HF_INTR, cpu_thread_schedule_intr);
    trap_install(TRAP_CPU_HALT, TRAP_HF_INTR, cpu_halt_intr);
    trap_install(TRAP_LAPIC_TIMER, TRAP_HF_INTR, lapic_timer_intr);
    trap_install(TRAP_LAPIC_ERROR, TRAP_HF_INTR, lapic_error_intr);
    trap_install(TRAP_LAPIC_SPURIOUS, TRAP_HF_INTR, lapic_spurious_intr);
}

void
trap_main(struct trap_frame *frame)
{
    struct trap_handler *handler;
    trap_handler_fn_t fn;

    assert(!cpu_intr_enabled());

    handler = trap_handler_get(frame->vector);

    if (handler->flags & TRAP_HF_INTR) {
        thread_intr_enter();
    }

    fn = atomic_load(&handler->fn, ATOMIC_RELAXED);
    fn(frame);

    if (handler->flags & TRAP_HF_INTR) {
        thread_intr_leave();
    }

    assert(!cpu_intr_enabled());
}

void
trap_register(unsigned int vector, trap_handler_fn_t handler_fn)
{
    unsigned long flags;

    spinlock_lock_intr_save(&trap_lock, &flags);
    trap_install(vector, TRAP_HF_INTR, handler_fn);
    spinlock_unlock_intr_restore(&trap_lock, flags);
}

#ifdef __LP64__

void
trap_frame_show(struct trap_frame *frame)
{
    printf("trap: rax: %016lx rbx: %016lx rcx: %016lx\n"
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
        printf("trap: cr2: %016lx\n", (unsigned long)cpu_get_cr2());
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

    printf("trap: eax: %08lx ebx: %08lx ecx: %08lx edx: %08lx\n"
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
        printf("trap: cr2: %08lx\n", (unsigned long)cpu_get_cr2());
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

void *
trap_get_interrupt_stack(const struct trap_frame *frame)
{
    struct trap_cpu_data *cpu_data;
    struct trap_handler *handler;

    handler = trap_handler_get(frame->vector);

    if ((handler->flags & TRAP_HF_INTR) && !thread_interrupted()) {
        cpu_data = cpu_local_ptr(trap_cpu_data);
        return cpu_data->intr_stack + sizeof(cpu_data->intr_stack);
    } else {
        return NULL;
    }
}
