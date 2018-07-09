/*
 * Copyright (c) 2010-2018 Richard Braun.
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

#include <assert.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <kern/atomic.h>
#include <kern/init.h>
#include <kern/kmem.h>
#include <kern/log.h>
#include <kern/macros.h>
#include <kern/panic.h>
#include <kern/percpu.h>
#include <kern/spinlock.h>
#include <kern/shutdown.h>
#include <kern/thread.h>
#include <kern/xcall.h>
#include <machine/acpi.h>
#include <machine/biosmem.h>
#include <machine/boot.h>
#include <machine/cpu.h>
#include <machine/io.h>
#include <machine/lapic.h>
#include <machine/page.h>
#include <machine/pit.h>
#include <machine/pmap.h>
#include <machine/ssp.h>
#include <machine/strace.h>
#include <vm/vm_page.h>

/*
 * Delay used for frequency measurement, in microseconds.
 */
#define CPU_FREQ_CAL_DELAY  1000000

#define CPU_CPUID_TYPE_MASK         0x00003000
#define CPU_CPUID_TYPE_SHIFT        12
#define CPU_CPUID_FAMILY_MASK       0x00000f00
#define CPU_CPUID_FAMILY_SHIFT      8
#define CPU_CPUID_EXTFAMILY_MASK    0x0ff00000
#define CPU_CPUID_EXTFAMILY_SHIFT   20
#define CPU_CPUID_MODEL_MASK        0x000000f0
#define CPU_CPUID_MODEL_SHIFT       4
#define CPU_CPUID_EXTMODEL_MASK     0x000f0000
#define CPU_CPUID_EXTMODEL_SHIFT    16
#define CPU_CPUID_STEPPING_MASK     0x0000000f
#define CPU_CPUID_STEPPING_SHIFT    0
#define CPU_CPUID_BRAND_MASK        0x000000ff
#define CPU_CPUID_BRAND_SHIFT       0
#define CPU_CPUID_CLFLUSH_MASK      0x0000ff00
#define CPU_CPUID_CLFLUSH_SHIFT     8
#define CPU_CPUID_APIC_ID_MASK      0xff000000
#define CPU_CPUID_APIC_ID_SHIFT     24

#define CPU_INVALID_APIC_ID ((unsigned int)-1)

struct cpu_vendor {
    unsigned int id;
    const char *str;
};

/*
 * IST indexes (0 means no stack switch).
 */
#define CPU_TSS_IST_INTR    1
#define CPU_TSS_IST_DF      2

/*
 * MP related CMOS ports, registers and values.
 */
#define CPU_MP_CMOS_PORT_REG        0x70
#define CPU_MP_CMOS_PORT_DATA       0x71
#define CPU_MP_CMOS_REG_RESET       0x0f
#define CPU_MP_CMOS_DATA_RESET_WARM 0x0a
#define CPU_MP_CMOS_RESET_VECTOR    0x467

/*
 * Priority of the shutdown operations.
 *
 * Last resort, lower than everything else.
 */
#define CPU_SHUTDOWN_PRIORITY 0

struct cpu_gate_desc {
    uint32_t word1;
    uint32_t word2;
#ifdef __LP64__
    uint32_t word3;
    uint32_t word4;
#endif /* __LP64__ */
};

struct cpu_idt {
    alignas(CPU_L1_SIZE) struct cpu_gate_desc descs[CPU_NR_EXC_VECTORS];
};

struct cpu_pseudo_desc {
    uint16_t limit;
    uintptr_t address;
} __packed;

#ifdef __LP64__

struct cpu_exc_frame {
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

struct cpu_exc_frame {
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

/*
 * Type for low level exception handlers.
 *
 * Low level exception handlers are directly installed in the IDT and are
 * first run by the processor when an exception occurs. They route execution
 * through either the main exception or interrupt handler.
 */
typedef void (*cpu_ll_exc_fn_t)(void);

typedef void (*cpu_exc_handler_fn_t)(const struct cpu_exc_frame *frame);

struct cpu_exc_handler {
    cpu_exc_handler_fn_t fn;
};

struct cpu_intr_handler {
    cpu_intr_handler_fn_t fn;
};

/*
 * Set the given GDT for the current processor.
 *
 * On i386, the ds, es and ss segment registers are reloaded.
 *
 * The fs and gs segment registers, which point to the percpu and the TLS
 * areas respectively, must be set separately.
 */
void cpu_load_gdt(struct cpu_pseudo_desc *gdtr);

/*
 * Return a pointer to the processor-local interrupt stack.
 *
 * This function is called by the low level exception handling code.
 *
 * Return NULL if no stack switching is required.
 */
void * cpu_get_intr_stack(void);

/*
 * Common entry points for exceptions and interrupts.
 */
void cpu_exc_main(const struct cpu_exc_frame *frame);
void cpu_intr_main(const struct cpu_exc_frame *frame);

void *cpu_local_area __percpu;

/*
 * CPU descriptor, one per CPU.
 */
struct cpu cpu_desc __percpu;

/*
 * Number of active processors.
 */
unsigned int cpu_nr_active __read_mostly = 1;

/*
 * Processor frequency, assumed fixed and equal on all processors.
 */
static uint64_t cpu_freq __read_mostly;

static const struct cpu_tls_seg cpu_tls_seg = {
    .ssp_guard_word = SSP_GUARD_WORD,
};

static struct cpu_idt cpu_idt;

/*
 * This table only exists during initialization, and is a way to
 * communicate the list of low level handlers from assembly to C.
 */
extern cpu_ll_exc_fn_t cpu_ll_exc_handler_addrs[CPU_NR_EXC_VECTORS];

static struct cpu_exc_handler cpu_exc_handlers[CPU_NR_EXC_VECTORS]
    __read_mostly;

static struct cpu_intr_handler cpu_intr_handlers[CPU_NR_EXC_VECTORS]
    __read_mostly;

static const struct cpu_vendor cpu_vendors[] = {
    { CPU_VENDOR_INTEL, "GenuineIntel" },
    { CPU_VENDOR_AMD,   "AuthenticAMD" },
};

static const char *cpu_feature_names[] = {
    [CPU_FEATURE_FPU]   = "fpu",
    [CPU_FEATURE_PSE]   = "pse",
    [CPU_FEATURE_PAE]   = "pae",
    [CPU_FEATURE_MSR]   = "msr",
    [CPU_FEATURE_CX8]   = "cx8",
    [CPU_FEATURE_APIC]  = "apic",
    [CPU_FEATURE_PGE]   = "pge",
    [CPU_FEATURE_1GP]   = "1gp",
    [CPU_FEATURE_LM]    = "lm",
};

static void __init
cpu_exc_handler_init(struct cpu_exc_handler *handler, cpu_exc_handler_fn_t fn)
{
    handler->fn = fn;
}

static void
cpu_exc_handler_run(const struct cpu_exc_handler *handler,
                    const struct cpu_exc_frame *frame)
{
    handler->fn(frame);
}

static void __init
cpu_intr_handler_init(struct cpu_intr_handler *handler,
                      cpu_intr_handler_fn_t fn)
{
    handler->fn = fn;
}

static void
cpu_intr_handler_run(const struct cpu_intr_handler *handler,
                     unsigned int vector)
{
    handler->fn(vector);
}

static cpu_ll_exc_fn_t __init
cpu_get_ll_exc_handler(unsigned int vector)
{
    assert(vector < ARRAY_SIZE(cpu_ll_exc_handler_addrs));
    return cpu_ll_exc_handler_addrs[vector];
}

static struct cpu_exc_handler *
cpu_get_exc_handler(unsigned int vector)
{
    assert(vector < ARRAY_SIZE(cpu_exc_handlers));
    return &cpu_exc_handlers[vector];
}

static void __init
cpu_register_exc(unsigned int vector, cpu_exc_handler_fn_t fn)
{
    cpu_exc_handler_init(cpu_get_exc_handler(vector), fn);
}

static struct cpu_intr_handler *
cpu_get_intr_handler(unsigned int vector)
{
    assert(vector < ARRAY_SIZE(cpu_intr_handlers));
    return &cpu_intr_handlers[vector];
}

void __init
cpu_register_intr(unsigned int vector, cpu_intr_handler_fn_t fn)
{
    cpu_intr_handler_init(cpu_get_intr_handler(vector), fn);
}

static void __init
cpu_gate_desc_init_intr(struct cpu_gate_desc *desc, cpu_ll_exc_fn_t fn,
                        unsigned int ist_index)
{
    uintptr_t addr;

    addr = (uintptr_t)fn;
    desc->word1 = (CPU_GDT_SEL_CODE << 16)
                  | (addr & CPU_DESC_GATE_OFFSET_LOW_MASK);
    desc->word2 = (addr & CPU_DESC_GATE_OFFSET_HIGH_MASK)
                  | CPU_DESC_PRESENT | CPU_DESC_TYPE_GATE_INTR;

#ifdef __LP64__
    desc->word2 |= ist_index & CPU_DESC_SEG_IST_MASK;
    desc->word3 = addr >> 32;
    desc->word4 = 0;
#else /* __LP64__ */
    (void)ist_index;
#endif /* __LP64__ */
}

#ifndef __LP64__
static void __init
cpu_gate_desc_init_task(struct cpu_gate_desc *desc, unsigned int tss_seg_sel)
{
    desc->word2 = CPU_DESC_PRESENT | CPU_DESC_TYPE_GATE_TASK;
    desc->word1 = tss_seg_sel << 16;
}
#endif /* __LP64__ */

static struct cpu_gate_desc * __init
cpu_idt_get_desc(struct cpu_idt *idt, unsigned int vector)
{
    assert(vector < ARRAY_SIZE(idt->descs));
    return &idt->descs[vector];
}

static void __init
cpu_idt_set_intr_gate(struct cpu_idt *idt, unsigned int vector,
                      cpu_ll_exc_fn_t fn)
{
    struct cpu_gate_desc *desc;

    desc = cpu_idt_get_desc(idt, vector);
    cpu_gate_desc_init_intr(desc, fn, CPU_TSS_IST_INTR);
}

static void __init
cpu_idt_setup_double_fault(struct cpu_idt *idt)
{
    struct cpu_gate_desc *desc;

    desc = cpu_idt_get_desc(idt, CPU_EXC_DF);

#ifdef __LP64__
    cpu_ll_exc_fn_t fn;

    fn = cpu_get_ll_exc_handler(CPU_EXC_DF);
    cpu_gate_desc_init_intr(desc, fn, CPU_TSS_IST_DF);
#else /* __LP64__ */
    cpu_gate_desc_init_task(desc, CPU_GDT_SEL_DF_TSS);
#endif /* __LP64__ */
}

static void
cpu_idt_load(const struct cpu_idt *idt)
{
    struct cpu_pseudo_desc idtr;

    idtr.address = (uintptr_t)idt->descs;
    idtr.limit = sizeof(idt->descs) - 1;
    asm volatile("lidt %0" : : "m" (idtr));
}

uint64_t
cpu_get_freq(void)
{
    return cpu_freq;
}

static uint64_t
cpu_get_tsc(void)
{
    uint32_t high, low;

    asm volatile("rdtsc" : "=a" (low), "=d" (high));
    return ((uint64_t)high << 32) | low;
}

void
cpu_delay(unsigned long usecs)
{
    int64_t total, prev, count, diff;

    assert(usecs != 0);

    total = DIV_CEIL((int64_t)usecs * cpu_freq, 1000000);
    prev = cpu_get_tsc();

    do {
        count = cpu_get_tsc();
        diff = count - prev;
        prev = count;
        total -= diff;
        cpu_pause();
    } while (total > 0);
}

void *
cpu_get_intr_stack(void)
{
    struct cpu *cpu;

    if (thread_interrupted()) {
        return NULL;
    }

    cpu = cpu_local_ptr(cpu_desc);
    return cpu->intr_stack + sizeof(cpu->intr_stack);
}

static void
cpu_show_thread(void)
{
    struct thread *thread;

    thread = thread_self();

    printf("cpu: interrupted thread: %p (%s)\n", thread, thread_name(thread));
}

#ifdef __LP64__

static void
cpu_show_frame(const struct cpu_exc_frame *frame)
{
    printf("cpu: rax: %016lx rbx: %016lx rcx: %016lx\n"
           "cpu: rdx: %016lx rbp: %016lx rsi: %016lx\n"
           "cpu: rdi: %016lx  r8: %016lx  r9: %016lx\n"
           "cpu: r10: %016lx r11: %016lx r12: %016lx\n"
           "cpu: r13: %016lx r14: %016lx r15: %016lx\n"
           "cpu: vector: %lu error: %08lx\n"
           "cpu: rip: %016lx cs: %lu rflags: %016lx\n"
           "cpu: rsp: %016lx ss: %lu\n",
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
        printf("cpu: cr2: %016lx\n", (unsigned long)cpu_get_cr2());
    }
}

#else /* __LP64__ */

static void
cpu_show_frame(const struct cpu_exc_frame *frame)
{
    unsigned long esp, ss;

    if ((frame->cs & CPU_PL_USER) || (frame->vector == CPU_EXC_DF)) {
        esp = frame->esp;
        ss = frame->ss;
    } else {
        esp = 0;
        ss = 0;
    }

    printf("cpu: eax: %08lx ebx: %08lx ecx: %08lx edx: %08lx\n"
           "cpu: ebp: %08lx esi: %08lx edi: %08lx\n"
           "cpu: ds: %hu es: %hu fs: %hu gs: %hu\n"
           "cpu: vector: %lu error: %08lx\n"
           "cpu: eip: %08lx cs: %lu eflags: %08lx\n"
           "cpu: esp: %08lx ss: %lu\n",
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
        printf("cpu: cr2: %08lx\n", (unsigned long)cpu_get_cr2());
    }
}

#endif /* __LP64__ */

static void
cpu_show_stack(const struct cpu_exc_frame *frame)
{
#ifdef __LP64__
    strace_show(frame->rip, frame->rbp);
#else /* __LP64__ */
    strace_show(frame->eip, frame->ebp);
#endif /* __LP64__ */
}

static void
cpu_exc_double_fault(const struct cpu_exc_frame *frame)
{
    cpu_halt_broadcast();

#ifndef __LP64__
    struct cpu_exc_frame frame_store;
    struct cpu *cpu;

    /*
     * Double faults are catched through a task gate, which makes the given
     * frame useless. The interrupted state is automatically saved in the
     * main TSS by the processor. Build a proper exception frame from there.
     */
    cpu = cpu_current();
    frame_store.eax = cpu->tss.eax;
    frame_store.ebx = cpu->tss.ebx;
    frame_store.ecx = cpu->tss.ecx;
    frame_store.edx = cpu->tss.edx;
    frame_store.ebp = cpu->tss.ebp;
    frame_store.esi = cpu->tss.esi;
    frame_store.edi = cpu->tss.edi;
    frame_store.ds = cpu->tss.ds;
    frame_store.es = cpu->tss.es;
    frame_store.fs = cpu->tss.fs;
    frame_store.gs = cpu->tss.gs;
    frame_store.vector = CPU_EXC_DF;
    frame_store.error = 0;
    frame_store.eip = cpu->tss.eip;
    frame_store.cs = cpu->tss.cs;
    frame_store.eflags = cpu->tss.eflags;
    frame_store.esp = cpu->tss.esp;
    frame_store.ss = cpu->tss.ss;
    frame = &frame_store;
#endif /* __LP64__ */

    printf("cpu: double fault (cpu%u):\n", cpu_id());
    cpu_show_thread();
    cpu_show_frame(frame);
    cpu_show_stack(frame);
    cpu_halt();
}

void
cpu_exc_main(const struct cpu_exc_frame *frame)
{
    const struct cpu_exc_handler *handler;

    handler = cpu_get_exc_handler(frame->vector);
    cpu_exc_handler_run(handler, frame);
    assert(!cpu_intr_enabled());
}

void
cpu_intr_main(const struct cpu_exc_frame *frame)
{
    const struct cpu_intr_handler *handler;

    handler = cpu_get_intr_handler(frame->vector);

    thread_intr_enter();
    cpu_intr_handler_run(handler, frame->vector);
    thread_intr_leave();

    assert(!cpu_intr_enabled());
}

static void
cpu_exc_default(const struct cpu_exc_frame *frame)
{
    cpu_halt_broadcast();
    printf("cpu: unregistered exception (cpu%u):\n", cpu_id());
    cpu_show_thread();
    cpu_show_frame(frame);
    cpu_show_stack(frame);
    cpu_halt();
}

static void
cpu_intr_default(unsigned int vector)
{
    cpu_halt_broadcast();
    printf("cpu: unregistered interrupt %u (cpu%u):\n", vector, cpu_id());
    cpu_show_thread();
    cpu_halt();
}

static void
cpu_xcall_intr(unsigned int vector)
{
    (void)vector;

    lapic_eoi();
    xcall_intr();
}

static void
cpu_thread_schedule_intr(unsigned int vector)
{
    (void)vector;

    lapic_eoi();
    thread_schedule_intr();
}

static void
cpu_halt_intr(unsigned int vector)
{
    (void)vector;

    lapic_eoi();
    cpu_halt();
}

static void __init
cpu_setup_idt(void)
{
    for (size_t i = 0; i < ARRAY_SIZE(cpu_ll_exc_handler_addrs); i++) {
        cpu_idt_set_intr_gate(&cpu_idt, i, cpu_get_ll_exc_handler(i));
    }

    cpu_idt_setup_double_fault(&cpu_idt);
}

static void __init
cpu_setup_intr(void)
{
    cpu_setup_idt();

    for (size_t i = 0; i < ARRAY_SIZE(cpu_exc_handlers); i++) {
        cpu_register_exc(i, cpu_exc_default);
    }

    /* Architecture defined exceptions */
    cpu_register_exc(CPU_EXC_DE, cpu_exc_default);
    cpu_register_exc(CPU_EXC_DB, cpu_exc_default);
    cpu_register_intr(CPU_EXC_NMI, cpu_intr_default);
    cpu_register_exc(CPU_EXC_BP, cpu_exc_default);
    cpu_register_exc(CPU_EXC_OF, cpu_exc_default);
    cpu_register_exc(CPU_EXC_BR, cpu_exc_default);
    cpu_register_exc(CPU_EXC_UD, cpu_exc_default);
    cpu_register_exc(CPU_EXC_NM, cpu_exc_default);
    cpu_register_exc(CPU_EXC_DF, cpu_exc_double_fault);
    cpu_register_exc(CPU_EXC_TS, cpu_exc_default);
    cpu_register_exc(CPU_EXC_NP, cpu_exc_default);
    cpu_register_exc(CPU_EXC_SS, cpu_exc_default);
    cpu_register_exc(CPU_EXC_GP, cpu_exc_default);
    cpu_register_exc(CPU_EXC_PF, cpu_exc_default);
    cpu_register_exc(CPU_EXC_MF, cpu_exc_default);
    cpu_register_exc(CPU_EXC_AC, cpu_exc_default);
    cpu_register_intr(CPU_EXC_MC, cpu_intr_default);
    cpu_register_exc(CPU_EXC_XM, cpu_exc_default);

    /* System defined exceptions */
    cpu_register_intr(CPU_EXC_XCALL, cpu_xcall_intr);
    cpu_register_intr(CPU_EXC_THREAD_SCHEDULE, cpu_thread_schedule_intr);
    cpu_register_intr(CPU_EXC_HALT, cpu_halt_intr);
}

static void __init
cpu_seg_desc_init_null(struct cpu_seg_desc *desc)
{
    desc->high = 0;
    desc->low = 0;
}

static void __init
cpu_seg_desc_init_code(struct cpu_seg_desc *desc)
{
#ifdef __LP64__
    desc->high = CPU_DESC_LONG | CPU_DESC_PRESENT | CPU_DESC_S
                 | CPU_DESC_TYPE_CODE;
    desc->low = 0;
#else /* __LP64__ */
    desc->high = CPU_DESC_GRAN_4KB | CPU_DESC_DB
                 | (0x000fffff & CPU_DESC_SEG_LIMIT_HIGH_MASK)
                 | CPU_DESC_PRESENT | CPU_DESC_S | CPU_DESC_TYPE_CODE;
    desc->low = 0x000fffff & CPU_DESC_SEG_LIMIT_LOW_MASK;
#endif /* __LP64__ */
}

static void __init
cpu_seg_desc_init_data(struct cpu_seg_desc *desc, uintptr_t base)
{
#ifdef __LP64__
    (void)base;

    desc->high = CPU_DESC_DB | CPU_DESC_PRESENT | CPU_DESC_S
                 | CPU_DESC_TYPE_DATA;
    desc->low = 0;
#else /* __LP64__ */
    desc->high = (base & CPU_DESC_SEG_BASE_HIGH_MASK)
                 | CPU_DESC_GRAN_4KB | CPU_DESC_DB
                 | (0x000fffff & CPU_DESC_SEG_LIMIT_HIGH_MASK)
                 | CPU_DESC_PRESENT | CPU_DESC_S | CPU_DESC_TYPE_DATA
                 | ((base & CPU_DESC_SEG_BASE_MID_MASK) >> 16);
    desc->low = ((base & CPU_DESC_SEG_BASE_LOW_MASK) << 16)
                | (0x000fffff & CPU_DESC_SEG_LIMIT_LOW_MASK);
#endif /* __LP64__ */
}

static void __init
cpu_sysseg_desc_init_tss(struct cpu_sysseg_desc *desc,
                         const struct cpu_tss *tss)
{
    uintptr_t base, limit;

    base = (uintptr_t)tss;
    limit = base + sizeof(*tss) - 1;

#ifdef __LP64__
    desc->word4 = 0;
    desc->word3 = (base >> 32);
#endif /* __LP64__ */
    desc->word2 = (base & CPU_DESC_SEG_BASE_HIGH_MASK)
                  | (limit & CPU_DESC_SEG_LIMIT_HIGH_MASK)
                  | CPU_DESC_PRESENT | CPU_DESC_TYPE_TSS
                  | ((base & CPU_DESC_SEG_BASE_MID_MASK) >> 16);
    desc->word1 = ((base & CPU_DESC_SEG_BASE_LOW_MASK) << 16)
                  | (limit & CPU_DESC_SEG_LIMIT_LOW_MASK);
}

static void * __init
cpu_gdt_get_desc(struct cpu_gdt *gdt, unsigned int selector)
{
    assert((selector % sizeof(struct cpu_seg_desc)) == 0);
    assert(selector < sizeof(gdt->descs));
    return gdt->descs + selector;
}

static void __init
cpu_gdt_set_null(struct cpu_gdt *gdt, unsigned int selector)
{
    struct cpu_seg_desc *desc;

    desc = cpu_gdt_get_desc(gdt, selector);
    cpu_seg_desc_init_null(desc);
}

static void __init
cpu_gdt_set_code(struct cpu_gdt *gdt, unsigned int selector)
{
    struct cpu_seg_desc *desc;

    desc = cpu_gdt_get_desc(gdt, selector);
    cpu_seg_desc_init_code(desc);
}

static void __init
cpu_gdt_set_data(struct cpu_gdt *gdt, unsigned int selector, const void *base)
{
    struct cpu_seg_desc *desc;

    desc = cpu_gdt_get_desc(gdt, selector);
    cpu_seg_desc_init_data(desc, (uintptr_t)base);
}

static void __init
cpu_gdt_set_tss(struct cpu_gdt *gdt, unsigned int selector,
                const struct cpu_tss *tss)
{
    struct cpu_sysseg_desc *desc;

    desc = cpu_gdt_get_desc(gdt, selector);
    cpu_sysseg_desc_init_tss(desc, tss);
}

static void __init
cpu_gdt_init(struct cpu_gdt *gdt, const struct cpu_tss *tss,
             const struct cpu_tss *df_tss, void *pcpu_area)
{
    cpu_gdt_set_null(gdt, CPU_GDT_SEL_NULL);
    cpu_gdt_set_code(gdt, CPU_GDT_SEL_CODE);
    cpu_gdt_set_data(gdt, CPU_GDT_SEL_DATA, 0);
    cpu_gdt_set_tss(gdt, CPU_GDT_SEL_TSS, tss);

#ifdef __LP64__
    (void)df_tss;
    (void)pcpu_area;
#else /* __LP64__ */
    cpu_gdt_set_tss(gdt, CPU_GDT_SEL_DF_TSS, df_tss);
    cpu_gdt_set_data(gdt, CPU_GDT_SEL_PERCPU, pcpu_area);
    cpu_gdt_set_data(gdt, CPU_GDT_SEL_TLS, &cpu_tls_seg);
#endif /* __LP64__ */
}

static void __init
cpu_gdt_load(const struct cpu_gdt *gdt)
{
    struct cpu_pseudo_desc gdtr;

    gdtr.address = (uintptr_t)gdt->descs;
    gdtr.limit = sizeof(gdt->descs) - 1;
    cpu_load_gdt(&gdtr);
}

static void __init
cpu_tss_init(struct cpu_tss *tss, const void *intr_stack_top,
             const void *df_stack_top)
{
    memset(tss, 0, sizeof(*tss));

#ifdef __LP64__
    tss->ist[CPU_TSS_IST_INTR] = (uintptr_t)intr_stack_top;
    tss->ist[CPU_TSS_IST_DF] = (uintptr_t)df_stack_top;
#else /* __LP64__ */
    (void)df_stack_top;
#endif /* __LP64__ */
}

#ifndef __LP64__
static void __init
cpu_tss_init_i386_double_fault(struct cpu_tss *tss, const void *df_stack_top)
{
    memset(tss, 0, sizeof(*tss));
    tss->cr3 = cpu_get_cr3();
    tss->eip = (uintptr_t)cpu_get_ll_exc_handler(CPU_EXC_DF);
    tss->eflags = CPU_EFL_ONE;
    tss->ebp = (uintptr_t)df_stack_top;
    tss->esp = tss->ebp;
    tss->es = CPU_GDT_SEL_DATA;
    tss->cs = CPU_GDT_SEL_CODE;
    tss->ss = CPU_GDT_SEL_DATA;
    tss->ds = CPU_GDT_SEL_DATA;
    tss->fs = CPU_GDT_SEL_PERCPU;
}
#endif /* __LP64__ */

static void __init
cpu_feature_map_init(struct cpu_feature_map *map)
{
    bitmap_zero(map->flags, CPU_NR_FEATURES);
}

static void __init
cpu_feature_map_cset(struct cpu_feature_map *map, unsigned int word,
                     unsigned int mask, enum cpu_feature feature)
{
    if (word & mask) {
        bitmap_set(map->flags, feature);
    }
}

static void __init
cpu_feature_map_basic1_edx(struct cpu_feature_map *map, unsigned int edx)
{
    cpu_feature_map_cset(map, edx, CPU_CPUID_BASIC1_EDX_FPU, CPU_FEATURE_FPU);
    cpu_feature_map_cset(map, edx, CPU_CPUID_BASIC1_EDX_PSE, CPU_FEATURE_PSE);
    cpu_feature_map_cset(map, edx, CPU_CPUID_BASIC1_EDX_PAE, CPU_FEATURE_PAE);
    cpu_feature_map_cset(map, edx, CPU_CPUID_BASIC1_EDX_MSR, CPU_FEATURE_MSR);
    cpu_feature_map_cset(map, edx, CPU_CPUID_BASIC1_EDX_CX8, CPU_FEATURE_CX8);
    cpu_feature_map_cset(map, edx, CPU_CPUID_BASIC1_EDX_APIC, CPU_FEATURE_APIC);
    cpu_feature_map_cset(map, edx, CPU_CPUID_BASIC1_EDX_PGE, CPU_FEATURE_PGE);
}

static void __init
cpu_feature_map_ext1_edx(struct cpu_feature_map *map, unsigned int edx)
{
    cpu_feature_map_cset(map, edx, CPU_CPUID_EXT1_EDX_1GP, CPU_FEATURE_1GP);
    cpu_feature_map_cset(map, edx, CPU_CPUID_EXT1_EDX_LM, CPU_FEATURE_LM);
}

static struct cpu_tss * __init
cpu_get_tss(struct cpu *cpu)
{
    return &cpu->tss;
}

static void * __init
cpu_get_intr_stack_top(struct cpu *cpu)
{
    return &cpu->intr_stack[sizeof(cpu->intr_stack)];
}

static struct cpu_tss * __init
cpu_get_df_tss(struct cpu *cpu)
{
#ifdef __LP64__
    (void)cpu;
    return NULL;
#else /* __LP64__ */
    return &cpu->df_tss;
#endif /* __LP64__ */
}

static void * __init
cpu_get_df_stack_top(struct cpu *cpu)
{
    return &cpu->df_stack[sizeof(cpu->df_stack)];
}

static void __init
cpu_init(struct cpu *cpu, unsigned int id, unsigned int apic_id)
{
    memset(cpu, 0, sizeof(*cpu));
    cpu->id = id;
    cpu->apic_id = apic_id;
}

static void __init
cpu_load_ldt(void)
{
    asm volatile("lldt %w0" : : "q" (CPU_GDT_SEL_NULL));
}

static void __init
cpu_load_tss(void)
{
    asm volatile("ltr %w0" : : "q" (CPU_GDT_SEL_TSS));
}

static void __init
cpu_set_percpu_area(const struct cpu *cpu, void *area)
{
#ifdef __LP64__
    unsigned long va;

    va = (unsigned long)area;
    cpu_set_msr(CPU_MSR_FSBASE, (uint32_t)(va >> 32), (uint32_t)va);
#else /* __LP64__ */
    asm volatile("mov %0, %%fs" : : "r" (CPU_GDT_SEL_PERCPU));
#endif /* __LP64__ */

    percpu_var(cpu_local_area, cpu->id) = area;
}

static void __init
cpu_set_tls_area(void)
{
#ifdef __LP64__
    uintptr_t va;

    va = (uintptr_t)&cpu_tls_seg;
    cpu_set_msr(CPU_MSR_GSBASE, (uint32_t)(va >> 32), (uint32_t)va);
#else /* __LP64__ */
    asm volatile("mov %0, %%gs" : : "r" (CPU_GDT_SEL_TLS));
#endif /* __LP64__ */
}

static const struct cpu_vendor * __init
cpu_vendor_lookup(const char *str)
{
    for (size_t i = 0; i < ARRAY_SIZE(cpu_vendors); i++) {
        if (strcmp(str, cpu_vendors[i].str) == 0) {
            return &cpu_vendors[i];
        }
    }

    return NULL;
}

static void __init
cpu_init_vendor_id(struct cpu *cpu)
{
    const struct cpu_vendor *vendor;

    vendor = cpu_vendor_lookup(cpu->vendor_str);

    if (vendor == NULL) {
        return;
    }

    cpu->vendor_id = vendor->id;
}

static void __init
cpu_build(struct cpu *cpu)
{
    unsigned int eax, ebx, ecx, edx, max_basic, max_extended;
    void *pcpu_area;

    pcpu_area = percpu_area(cpu->id);

    /*
     * Assume at least an i586 processor.
     */

    cpu_intr_restore(CPU_EFL_ONE);
    cpu_set_cr0(CPU_CR0_PG | CPU_CR0_AM | CPU_CR0_WP | CPU_CR0_NE | CPU_CR0_ET
                | CPU_CR0_TS | CPU_CR0_MP | CPU_CR0_PE);
    cpu_gdt_init(&cpu->gdt, cpu_get_tss(cpu), cpu_get_df_tss(cpu), pcpu_area);
    cpu_gdt_load(&cpu->gdt);
    cpu_load_ldt();
    cpu_tss_init(&cpu->tss, cpu_get_intr_stack_top(cpu),
                 cpu_get_df_stack_top(cpu));
#ifndef __LP64__
    cpu_tss_init_i386_double_fault(&cpu->df_tss, cpu_get_df_stack_top(cpu));
#endif /* __LP64__ */
    cpu_load_tss();
    cpu_idt_load(&cpu_idt);
    cpu_set_percpu_area(cpu, pcpu_area);
    cpu_set_tls_area();

    /*
     * Perform the check after initializing the GDT and the per-CPU area
     * since cpu_id() relies on them to correctly work.
     */
    assert(cpu->id == cpu_id());

    eax = 0;
    cpu_cpuid(&eax, &ebx, &ecx, &edx);
    max_basic = eax;
    cpu->cpuid_max_basic = max_basic;
    memcpy(cpu->vendor_str, &ebx, sizeof(ebx));
    memcpy(cpu->vendor_str + 4, &edx, sizeof(edx));
    memcpy(cpu->vendor_str + 8, &ecx, sizeof(ecx));
    cpu->vendor_str[sizeof(cpu->vendor_str) - 1] = '\0';
    cpu_init_vendor_id(cpu);

    /* Some fields are only initialized if supported by the processor */
    cpu->model_name[0] = '\0';
    cpu->phys_addr_width = 0;
    cpu->virt_addr_width = 0;

    assert(max_basic >= 1);

    eax = 1;
    cpu_cpuid(&eax, &ebx, &ecx, &edx);
    cpu->type = (eax & CPU_CPUID_TYPE_MASK) >> CPU_CPUID_TYPE_SHIFT;
    cpu->family = (eax & CPU_CPUID_FAMILY_MASK) >> CPU_CPUID_FAMILY_SHIFT;

    if (cpu->family == 0xf) {
        cpu->family += (eax & CPU_CPUID_EXTFAMILY_MASK)
                       >> CPU_CPUID_EXTFAMILY_SHIFT;
    }

    cpu->model = (eax & CPU_CPUID_MODEL_MASK) >> CPU_CPUID_MODEL_SHIFT;

    if ((cpu->model == 6) || (cpu->model == 0xf)) {
        cpu->model += (eax & CPU_CPUID_EXTMODEL_MASK)
                      >> CPU_CPUID_EXTMODEL_SHIFT;
    }

    cpu->stepping = (eax & CPU_CPUID_STEPPING_MASK)
                    >> CPU_CPUID_STEPPING_SHIFT;
    cpu->clflush_size = ((ebx & CPU_CPUID_CLFLUSH_MASK)
                         >> CPU_CPUID_CLFLUSH_SHIFT) * 8;
    cpu->initial_apic_id = (ebx & CPU_CPUID_APIC_ID_MASK)
                           >> CPU_CPUID_APIC_ID_SHIFT;
    cpu_feature_map_init(&cpu->feature_map);
    cpu_feature_map_basic1_edx(&cpu->feature_map, edx);

    eax = CPU_CPUID_EXT_BIT;
    cpu_cpuid(&eax, &ebx, &ecx, &edx);

    if (eax <= CPU_CPUID_EXT_BIT) {
        max_extended = 0;
    } else {
        max_extended = eax;
    }

    cpu->cpuid_max_extended = max_extended;

    if (max_extended >= (CPU_CPUID_EXT_BIT | 1)) {
        eax = CPU_CPUID_EXT_BIT | 1;
        cpu_cpuid(&eax, &ebx, &ecx, &edx);
        cpu_feature_map_ext1_edx(&cpu->feature_map, edx);
    }

    if (max_extended >= (CPU_CPUID_EXT_BIT | 4)) {
        eax = CPU_CPUID_EXT_BIT | 2;
        cpu_cpuid(&eax, &ebx, &ecx, &edx);
        memcpy(cpu->model_name, &eax, sizeof(eax));
        memcpy(cpu->model_name + 4, &ebx, sizeof(ebx));
        memcpy(cpu->model_name + 8, &ecx, sizeof(ecx));
        memcpy(cpu->model_name + 12, &edx, sizeof(edx));

        eax = CPU_CPUID_EXT_BIT | 3;
        cpu_cpuid(&eax, &ebx, &ecx, &edx);
        memcpy(cpu->model_name + 16, &eax, sizeof(eax));
        memcpy(cpu->model_name + 20, &ebx, sizeof(ebx));
        memcpy(cpu->model_name + 24, &ecx, sizeof(ecx));
        memcpy(cpu->model_name + 28, &edx, sizeof(edx));

        eax = CPU_CPUID_EXT_BIT | 4;
        cpu_cpuid(&eax, &ebx, &ecx, &edx);
        memcpy(cpu->model_name + 32, &eax, sizeof(eax));
        memcpy(cpu->model_name + 36, &ebx, sizeof(ebx));
        memcpy(cpu->model_name + 40, &ecx, sizeof(ecx));
        memcpy(cpu->model_name + 44, &edx, sizeof(edx));

        cpu->model_name[sizeof(cpu->model_name) - 1] = '\0';
    }

    if (max_extended >= (CPU_CPUID_EXT_BIT | 8)) {
        eax = CPU_CPUID_EXT_BIT | 8;
        cpu_cpuid(&eax, &ebx, &ecx, &edx);
        cpu->phys_addr_width = (unsigned short)eax & 0xff;
        cpu->virt_addr_width = ((unsigned short)eax >> 8) & 0xff;
    }

    atomic_store(&cpu->started, 1, ATOMIC_RELEASE);
}

static void __init
cpu_measure_freq(void)
{
    uint64_t start, end;

    pit_setup_free_running();

    start = cpu_get_tsc();
    pit_delay(CPU_FREQ_CAL_DELAY);
    end = cpu_get_tsc();

    cpu_freq = (end - start) / (1000000 / CPU_FREQ_CAL_DELAY);
}

static int __init
cpu_setup(void)
{
    struct cpu *cpu;

    cpu_setup_intr();

    cpu = percpu_ptr(cpu_desc, 0);
    cpu_init(cpu, 0, CPU_INVALID_APIC_ID);
    cpu_build(cpu);

    cpu_measure_freq();

    return 0;
}

INIT_OP_DEFINE(cpu_setup,
               INIT_OP_DEP(percpu_bootstrap, true));

static void __init
cpu_panic_on_missing_feature(const char *feature)
{
    panic("cpu: %s feature missing", feature);
}

static void __init
cpu_check(const struct cpu *cpu)
{
    if (!cpu_has_feature(cpu, CPU_FEATURE_FPU)) {
        cpu_panic_on_missing_feature("fpu");
    }

    /*
     * The compiler is expected to produce cmpxchg8b instructions to
     * perform 64-bits atomic operations on a 32-bits processor. Clang
     * currently has trouble doing that so 64-bits atomic support is
     * just disabled when building with it.
     */
#if !defined(__LP64__) && !defined(__clang__)
    if (!cpu_has_feature(cpu, CPU_FEATURE_CX8)) {
        cpu_panic_on_missing_feature("cx8");
    }
#endif
}

static int __init
cpu_check_bsp(void)
{
    cpu_check(cpu_current());
    return 0;
}

// TODO Remove panic_setup
INIT_OP_DEFINE(cpu_check_bsp,
               INIT_OP_DEP(cpu_setup, true),
               INIT_OP_DEP(panic_setup, true));

void __init
cpu_log_info(const struct cpu *cpu)
{
    char features[60], *ptr;
    size_t size, bytes;

    log_info("cpu%u: %s, type %u, family %u, model %u, stepping %u",
             cpu->id, cpu->vendor_str, cpu->type, cpu->family, cpu->model,
             cpu->stepping);

    if (strlen(cpu->model_name) > 0) {
        log_info("cpu%u: %s", cpu->id, cpu->model_name);
    }

    if ((cpu->phys_addr_width != 0) && (cpu->virt_addr_width != 0)) {
        log_info("cpu%u: address widths: physical: %hu, virtual: %hu",
                 cpu->id, cpu->phys_addr_width, cpu->virt_addr_width);
    }

    log_info("cpu%u: frequency: %llu.%02llu MHz", cpu->id,
             (unsigned long long)cpu_freq / 1000000,
             (unsigned long long)cpu_freq % 1000000);

    ptr = features;
    size = sizeof(features);

    for (size_t i = 0; i < ARRAY_SIZE(cpu_feature_names); i++) {
        if (!cpu_has_feature(cpu, i)) {
            continue;
        }

        assert(strlen(cpu_feature_names[i]) < sizeof(features));
        bytes = snprintf(ptr, size, " %s", cpu_feature_names[i]);

        if (bytes >= size) {
            *ptr = '\0';
            log_info("cpu%u:%s", cpu->id, features);
            ptr = features;
            size = sizeof(features);
            i--;
            continue;
        }

        ptr += bytes;
        size -= bytes;
    }

    log_info("cpu%u:%s", cpu->id, features);
}

void __init
cpu_mp_register_lapic(unsigned int apic_id, bool is_bsp)
{
    struct cpu *cpu;
    int error;

    if (is_bsp) {
        cpu = percpu_ptr(cpu_desc, 0);

        if (cpu->apic_id != CPU_INVALID_APIC_ID) {
            panic("cpu: another processor pretends to be the BSP");
        }

        cpu->apic_id = apic_id;
        return;
    }

    error = percpu_add(cpu_nr_active);

    if (error) {
        return;
    }

    cpu = percpu_ptr(cpu_desc, cpu_nr_active);
    cpu_init(cpu, cpu_nr_active, apic_id);
    cpu_nr_active++;
}

static void
cpu_trigger_double_fault(void)
{
    asm volatile("movl $0xdead, %esp; push $0");
}

static void
cpu_shutdown_reset(void)
{
    /* Generate a triple fault */
    cpu_idt_load(NULL);
    cpu_trigger_double_fault();
}

static struct shutdown_ops cpu_shutdown_ops = {
    .reset = cpu_shutdown_reset,
};

static int __init
cpu_mp_probe(void)
{
    log_info("cpu: %u processor(s) configured", cpu_count());
    return 0;
}

INIT_OP_DEFINE(cpu_mp_probe,
               INIT_OP_DEP(acpi_setup, true),
               INIT_OP_DEP(cpu_setup, true),
               INIT_OP_DEP(log_setup, true));

static int __init
cpu_setup_shutdown(void)
{
    if (cpu_count() == 1) {
        shutdown_register(&cpu_shutdown_ops, CPU_SHUTDOWN_PRIORITY);
    }

    return 0;
}

INIT_OP_DEFINE(cpu_setup_shutdown,
               INIT_OP_DEP(cpu_mp_probe, true),
               INIT_OP_DEP(shutdown_bootstrap, true));

void __init
cpu_mp_setup(void)
{
    uint16_t reset_vector[2];
    unsigned int started;
    struct cpu *cpu;
    void *ptr;

    if (cpu_count() == 1) {
        pmap_mp_setup();
        return;
    }

    assert(BOOT_MP_TRAMPOLINE_ADDR < BIOSMEM_BASE);
    assert(vm_page_aligned(BOOT_MP_TRAMPOLINE_ADDR));
    assert(boot_mp_trampoline_size <= PAGE_SIZE);

    /* Set up the AP trampoline code */
    ptr = (void *)vm_page_direct_va(BOOT_MP_TRAMPOLINE_ADDR);
    memcpy(ptr, boot_mp_trampoline, boot_mp_trampoline_size);

    /* Set up the warm reset vector */
    reset_vector[0] = 0;
    reset_vector[1] = BOOT_MP_TRAMPOLINE_ADDR >> 4;
    ptr = (void *)vm_page_direct_va(CPU_MP_CMOS_RESET_VECTOR);
    memcpy(ptr, reset_vector, sizeof(reset_vector));

    io_write_byte(CPU_MP_CMOS_PORT_REG, CPU_MP_CMOS_REG_RESET);
    io_write_byte(CPU_MP_CMOS_PORT_DATA, CPU_MP_CMOS_DATA_RESET_WARM);

    boot_alloc_ap_stacks();

    /*
     * This function creates per-CPU copies of the page tables. Just in case,
     * call it last to make sure all processors get the same mappings.
     */
    pmap_mp_setup();

    for (unsigned int i = 1; i < cpu_count(); i++) {
        cpu = percpu_ptr(cpu_desc, i);
        boot_set_ap_id(i);

        /* Perform the "Universal Start-up Algorithm" */
        lapic_ipi_init_assert(cpu->apic_id);
        cpu_delay(200);
        lapic_ipi_init_deassert(cpu->apic_id);
        cpu_delay(10000);
        lapic_ipi_startup(cpu->apic_id, BOOT_MP_TRAMPOLINE_ADDR >> 12);
        cpu_delay(200);
        lapic_ipi_startup(cpu->apic_id, BOOT_MP_TRAMPOLINE_ADDR >> 12);
        cpu_delay(200);

        for (;;) {
            started = atomic_load(&cpu->started, ATOMIC_ACQUIRE);

            if (started) {
                break;
            }
        }
    }
}

void __init
cpu_ap_setup(unsigned int ap_id)
{
    struct cpu *cpu;

    cpu = percpu_ptr(cpu_desc, ap_id);
    cpu_build(cpu);
    cpu_check(cpu_current());
    lapic_ap_setup();
}

void
cpu_halt_broadcast(void)
{
    unsigned int nr_cpus;

    assert(!cpu_intr_enabled());

    nr_cpus = cpu_count();

    if (nr_cpus == 1) {
        return;
    }

    lapic_ipi_broadcast(CPU_EXC_HALT);
}
