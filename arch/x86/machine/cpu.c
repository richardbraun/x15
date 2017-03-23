/*
 * Copyright (c) 2010-2017 Richard Braun.
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

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <kern/assert.h>
#include <kern/init.h>
#include <kern/macros.h>
#include <kern/panic.h>
#include <kern/param.h>
#include <kern/percpu.h>
#include <kern/thread.h>
#include <kern/xcall.h>
#include <machine/acpimp.h>
#include <machine/biosmem.h>
#include <machine/boot.h>
#include <machine/cpu.h>
#include <machine/io.h>
#include <machine/lapic.h>
#include <machine/mb.h>
#include <machine/pmap.h>
#include <machine/trap.h>
#include <vm/vm_page.h>

#define CPU_TYPE_MASK       0x00003000
#define CPU_TYPE_SHIFT      12
#define CPU_FAMILY_MASK     0x00000f00
#define CPU_FAMILY_SHIFT    8
#define CPU_EXTFAMILY_MASK  0x0ff00000
#define CPU_EXTFAMILY_SHIFT 20
#define CPU_MODEL_MASK      0x000000f0
#define CPU_MODEL_SHIFT     4
#define CPU_EXTMODEL_MASK   0x000f0000
#define CPU_EXTMODEL_SHIFT  16
#define CPU_STEPPING_MASK   0x0000000f
#define CPU_STEPPING_SHIFT  0
#define CPU_BRAND_MASK      0x000000ff
#define CPU_BRAND_SHIFT     0
#define CPU_CLFLUSH_MASK    0x0000ff00
#define CPU_CLFLUSH_SHIFT   8
#define CPU_APIC_ID_MASK    0xff000000
#define CPU_APIC_ID_SHIFT   24

#define CPU_INVALID_APIC_ID ((unsigned int)-1)

/*
 * MP related CMOS ports, registers and values.
 */
#define CPU_MP_CMOS_PORT_REG        0x70
#define CPU_MP_CMOS_PORT_DATA       0x71
#define CPU_MP_CMOS_REG_RESET       0x0f
#define CPU_MP_CMOS_DATA_RESET_WARM 0x0a
#define CPU_MP_CMOS_RESET_VECTOR    0x467

/*
 * Gate/segment descriptor bits and masks.
 */
#define CPU_DESC_TYPE_DATA              0x00000200
#define CPU_DESC_TYPE_CODE              0x00000a00
#define CPU_DESC_TYPE_TSS               0x00000900
#define CPU_DESC_TYPE_GATE_INTR         0x00000e00
#define CPU_DESC_TYPE_GATE_TASK         0x00000500
#define CPU_DESC_S                      0x00001000
#define CPU_DESC_PRESENT                0x00008000
#define CPU_DESC_LONG                   0x00200000
#define CPU_DESC_DB                     0x00400000
#define CPU_DESC_GRAN_4KB               0x00800000

#define CPU_DESC_GATE_OFFSET_LOW_MASK   0x0000ffff
#define CPU_DESC_GATE_OFFSET_HIGH_MASK  0xffff0000
#define CPU_DESC_SEG_IST_MASK           0x00000007
#define CPU_DESC_SEG_BASE_LOW_MASK      0x0000ffff
#define CPU_DESC_SEG_BASE_MID_MASK      0x00ff0000
#define CPU_DESC_SEG_BASE_HIGH_MASK     0xff000000
#define CPU_DESC_SEG_LIMIT_LOW_MASK     0x0000ffff
#define CPU_DESC_SEG_LIMIT_HIGH_MASK    0x000f0000

/*
 * Gate descriptor.
 */
struct cpu_gate_desc {
    uint32_t word1;
    uint32_t word2;
#ifdef __LP64__
    uint32_t word3;
    uint32_t word4;
#endif /* __LP64__ */
};

/*
 * Code or data segment descriptor.
 */
struct cpu_seg_desc {
    uint32_t low;
    uint32_t high;
};

/*
 * LDT or TSS system segment descriptor.
 */
struct cpu_sysseg_desc {
    uint32_t word1;
    uint32_t word2;
#ifdef __LP64__
    uint32_t word3;
    uint32_t word4;
#endif /* __LP64__ */
};

struct cpu_pseudo_desc {
    uint16_t limit;
    unsigned long address;
} __packed;

void *cpu_local_area __percpu;

/*
 * Processor descriptor, one per CPU.
 */
struct cpu cpu_desc __percpu;

/*
 * Number of active processors.
 */
unsigned int cpu_nr_active __read_mostly;

/*
 * Interrupt descriptor table.
 */
static struct cpu_gate_desc cpu_idt[CPU_IDT_SIZE] __aligned(8) __read_mostly;

/*
 * Double fault handler, and stack for the main processor.
 *
 * TODO Declare as init data, and replace the BSP stack with kernel virtual
 * memory.
 */
static unsigned long cpu_double_fault_handler;
static char cpu_double_fault_stack[STACK_SIZE] __aligned(DATA_ALIGN);

void * __init
cpu_get_boot_stack(void)
{
    return percpu_var(cpu_desc.boot_stack, boot_ap_id);
}

static void __init
cpu_preinit(struct cpu *cpu, unsigned int id, unsigned int apic_id)
{
    cpu->id = id;
    cpu->apic_id = apic_id;
    cpu->state = CPU_STATE_OFF;
    cpu->boot_stack = NULL;
}

static void
cpu_seg_set_null(char *table, unsigned int selector)
{
    struct cpu_seg_desc *desc;

    desc = (struct cpu_seg_desc *)(table + selector);
    desc->high = 0;
    desc->low = 0;
}

static void
cpu_seg_set_code(char *table, unsigned int selector)
{
    struct cpu_seg_desc *desc;

    desc = (struct cpu_seg_desc *)(table + selector);

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

static void
cpu_seg_set_data(char *table, unsigned int selector, uint32_t base)
{
    struct cpu_seg_desc *desc;

    desc = (struct cpu_seg_desc *)(table + selector);

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

static void
cpu_seg_set_tss(char *table, unsigned int selector, struct cpu_tss *tss)
{
    struct cpu_sysseg_desc *desc;
    unsigned long base, limit;

    desc = (struct cpu_sysseg_desc *)(table + selector);
    base = (unsigned long)tss;
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

/*
 * Set the given GDT for the current processor.
 *
 * On i386, the ds, es and ss segment registers are reloaded. In any case,
 * the gs segment register is set to the null selector. The fs segment
 * register, which points to the percpu area, must be set separately.
 */
void cpu_load_gdt(struct cpu_pseudo_desc *gdtr);

static inline void __init
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
cpu_init_gdtr(struct cpu_pseudo_desc *gdtr, const struct cpu *cpu)
{
    gdtr->address = (unsigned long)cpu->gdt;
    gdtr->limit = sizeof(cpu->gdt) - 1;
}

static void __init
cpu_init_gdt(struct cpu *cpu)
{
    struct cpu_pseudo_desc gdtr;
    void *pcpu_area;

    pcpu_area = percpu_area(cpu->id);

    cpu_seg_set_null(cpu->gdt, CPU_GDT_SEL_NULL);
    cpu_seg_set_code(cpu->gdt, CPU_GDT_SEL_CODE);
    cpu_seg_set_data(cpu->gdt, CPU_GDT_SEL_DATA, 0);
    cpu_seg_set_tss(cpu->gdt, CPU_GDT_SEL_TSS, &cpu->tss);

#ifndef __LP64__
    cpu_seg_set_tss(cpu->gdt, CPU_GDT_SEL_DF_TSS, &cpu->double_fault_tss);
    cpu_seg_set_data(cpu->gdt, CPU_GDT_SEL_PERCPU, (unsigned long)pcpu_area);
#endif /* __LP64__ */

    cpu_init_gdtr(&gdtr, cpu);
    cpu_load_gdt(&gdtr);
    cpu_set_percpu_area(cpu, pcpu_area);
}

static void __init
cpu_init_ldt(void)
{
    asm volatile("lldt %w0" : : "q" (CPU_GDT_SEL_NULL));
}

static void __init
cpu_init_tss(struct cpu *cpu)
{
    struct cpu_tss *tss;

    tss = &cpu->tss;
    memset(tss, 0, sizeof(*tss));

#ifdef __LP64__
    assert(cpu->double_fault_stack != NULL);
    tss->ist[CPU_TSS_IST_DF] = (unsigned long)cpu->double_fault_stack
                               + STACK_SIZE;
#endif /* __LP64__ */

    asm volatile("ltr %w0" : : "q" (CPU_GDT_SEL_TSS));
}

#ifndef __LP64__
static void __init
cpu_init_double_fault_tss(struct cpu *cpu)
{
    struct cpu_tss *tss;

    assert(cpu_double_fault_handler != 0);
    assert(cpu->double_fault_stack != NULL);

    tss = &cpu->double_fault_tss;
    memset(tss, 0, sizeof(*tss));
    tss->cr3 = cpu_get_cr3();
    tss->eip = cpu_double_fault_handler;
    tss->eflags = CPU_EFL_ONE;
    tss->ebp = (unsigned long)cpu->double_fault_stack + STACK_SIZE;
    tss->esp = tss->ebp;
    tss->es = CPU_GDT_SEL_DATA;
    tss->cs = CPU_GDT_SEL_CODE;
    tss->ss = CPU_GDT_SEL_DATA;
    tss->ds = CPU_GDT_SEL_DATA;
    tss->fs = CPU_GDT_SEL_PERCPU;
}
#endif /* __LP64__ */

void
cpu_idt_set_gate(unsigned int vector, void (*isr)(void))
{
    struct cpu_gate_desc *desc;

    assert(vector < ARRAY_SIZE(cpu_idt));

    desc = &cpu_idt[vector];

#ifdef __LP64__
    desc->word4 = 0;
    desc->word3 = (unsigned long)isr >> 32;
#endif /* __LP64__ */

    /* Use interrupt gates only to simplify trap handling */
    desc->word2 = ((unsigned long)isr & CPU_DESC_GATE_OFFSET_HIGH_MASK)
                  | CPU_DESC_PRESENT | CPU_DESC_TYPE_GATE_INTR;
    desc->word1 = (CPU_GDT_SEL_CODE << 16)
                  | ((unsigned long)isr & CPU_DESC_GATE_OFFSET_LOW_MASK);
}

void
cpu_idt_set_double_fault(void (*isr)(void))
{
    struct cpu_gate_desc *desc;

    cpu_double_fault_handler = (unsigned long)isr;

#ifdef __LP64__
    cpu_idt_set_gate(TRAP_DF, isr);
    desc = &cpu_idt[TRAP_DF];
    desc->word2 |= CPU_TSS_IST_DF & CPU_DESC_SEG_IST_MASK;
#else /* __LP64__ */
    desc = &cpu_idt[TRAP_DF];
    desc->word2 = CPU_DESC_PRESENT | CPU_DESC_TYPE_GATE_TASK;
    desc->word1 = CPU_GDT_SEL_DF_TSS << 16;
#endif /* __LP64__ */
}

static void
cpu_load_idt(void)
{
    static volatile struct cpu_pseudo_desc idtr;

    idtr.address = (unsigned long)cpu_idt;
    idtr.limit = sizeof(cpu_idt) - 1;
    asm volatile("lidt %0" : : "m" (idtr));
}

/*
 * Initialize the given cpu structure for the current processor.
 */
static void __init
cpu_init(struct cpu *cpu)
{
    unsigned int eax, ebx, ecx, edx, max_basic, max_extended;

    /*
     * Assume at least an i586 processor.
     */

    cpu_intr_restore(CPU_EFL_ONE);
    cpu_set_cr0(CPU_CR0_PG | CPU_CR0_AM | CPU_CR0_WP | CPU_CR0_NE | CPU_CR0_ET
                | CPU_CR0_TS | CPU_CR0_MP | CPU_CR0_PE);
    cpu_init_gdt(cpu);
    cpu_init_ldt();
    cpu_init_tss(cpu);
#ifndef __LP64__
    cpu_init_double_fault_tss(cpu);
#endif /* __LP64__ */
    cpu_load_idt();

    eax = 0;
    cpu_cpuid(&eax, &ebx, &ecx, &edx);
    max_basic = eax;
    memcpy(cpu->vendor_id, &ebx, sizeof(ebx));
    memcpy(cpu->vendor_id + 4, &edx, sizeof(edx));
    memcpy(cpu->vendor_id + 8, &ecx, sizeof(ecx));
    cpu->vendor_id[sizeof(cpu->vendor_id) - 1] = '\0';

    /* Some fields are only initialized if supported by the processor */
    cpu->model_name[0] = '\0';
    cpu->phys_addr_width = 0;
    cpu->virt_addr_width = 0;

    assert(max_basic >= 1);

    eax = 1;
    cpu_cpuid(&eax, &ebx, &ecx, &edx);
    cpu->type = (eax & CPU_TYPE_MASK) >> CPU_TYPE_SHIFT;
    cpu->family = (eax & CPU_FAMILY_MASK) >> CPU_FAMILY_SHIFT;

    if (cpu->family == 0xf) {
        cpu->family += (eax & CPU_EXTFAMILY_MASK) >> CPU_EXTFAMILY_SHIFT;
    }

    cpu->model = (eax & CPU_MODEL_MASK) >> CPU_MODEL_SHIFT;

    if ((cpu->model == 6) || (cpu->model == 0xf)) {
        cpu->model += (eax & CPU_EXTMODEL_MASK) >> CPU_EXTMODEL_SHIFT;
    }

    cpu->stepping = (eax & CPU_STEPPING_MASK) >> CPU_STEPPING_SHIFT;
    cpu->clflush_size = ((ebx & CPU_CLFLUSH_MASK) >> CPU_CLFLUSH_SHIFT) * 8;
    cpu->initial_apic_id = (ebx & CPU_APIC_ID_MASK) >> CPU_APIC_ID_SHIFT;
    cpu->features1 = ecx;
    cpu->features2 = edx;

    eax = 0x80000000;
    cpu_cpuid(&eax, &ebx, &ecx, &edx);

    if (eax <= 0x80000000) {
        max_extended = 0;
    } else {
        max_extended = eax;
    }

    if (max_extended < 0x80000001) {
        cpu->features3 = 0;
        cpu->features4 = 0;
    } else {
        eax = 0x80000001;
        cpu_cpuid(&eax, &ebx, &ecx, &edx);
        cpu->features3 = ecx;
        cpu->features4 = edx;
    }

    if (max_extended >= 0x80000004) {
        eax = 0x80000002;
        cpu_cpuid(&eax, &ebx, &ecx, &edx);
        memcpy(cpu->model_name, &eax, sizeof(eax));
        memcpy(cpu->model_name + 4, &ebx, sizeof(ebx));
        memcpy(cpu->model_name + 8, &ecx, sizeof(ecx));
        memcpy(cpu->model_name + 12, &edx, sizeof(edx));

        eax = 0x80000003;
        cpu_cpuid(&eax, &ebx, &ecx, &edx);
        memcpy(cpu->model_name + 16, &eax, sizeof(eax));
        memcpy(cpu->model_name + 20, &ebx, sizeof(ebx));
        memcpy(cpu->model_name + 24, &ecx, sizeof(ecx));
        memcpy(cpu->model_name + 28, &edx, sizeof(edx));

        eax = 0x80000004;
        cpu_cpuid(&eax, &ebx, &ecx, &edx);
        memcpy(cpu->model_name + 32, &eax, sizeof(eax));
        memcpy(cpu->model_name + 36, &ebx, sizeof(ebx));
        memcpy(cpu->model_name + 40, &ecx, sizeof(ecx));
        memcpy(cpu->model_name + 44, &edx, sizeof(edx));

        cpu->model_name[sizeof(cpu->model_name) - 1] = '\0';
    }

    if (max_extended >= 0x80000008) {
        eax = 0x80000008;
        cpu_cpuid(&eax, &ebx, &ecx, &edx);
        cpu->phys_addr_width = (unsigned short)eax & 0xff;
        cpu->virt_addr_width = ((unsigned short)eax >> 8) & 0xff;
    }

    cpu->state = CPU_STATE_ON;
}

void __init
cpu_setup(void)
{
    struct cpu *cpu;

    cpu = percpu_ptr(cpu_desc, 0);
    cpu_preinit(cpu, 0, CPU_INVALID_APIC_ID);
    cpu->double_fault_stack = cpu_double_fault_stack; /* XXX */
    cpu_init(cpu);
    cpu_nr_active = 1;
}

static void __init
cpu_panic_on_missing_feature(const char *feature)
{
    panic("cpu: %s feature missing", feature);
}

void __init
cpu_check(const struct cpu *cpu)
{
    if (!(cpu->features2 & CPU_FEATURE2_FPU)) {
        cpu_panic_on_missing_feature("fpu");
    }

    /* TODO: support UP with legacy PIC machines */
    if (!(cpu->features2 & CPU_FEATURE2_APIC)) {
        cpu_panic_on_missing_feature("apic");
    }

    /*
     * The compiler is expected to produce cmpxchg8b instructions to
     * perform 64-bits atomic operations on a 32-bits processor. Clang
     * currently has trouble doing that so 64-bits atomic support is
     * just disabled when building with it.
     */
#if !defined(__LP64__) && !defined(__clang__)
    if (!(cpu->features2 & CPU_FEATURE2_CX8)) {
        cpu_panic_on_missing_feature("cx8");
    }
#endif
}

void
cpu_info(const struct cpu *cpu)
{
    printf("cpu%u: %s, type %u, family %u, model %u, stepping %u\n",
           cpu->id, cpu->vendor_id, cpu->type, cpu->family, cpu->model,
           cpu->stepping);

    if (strlen(cpu->model_name) > 0) {
        printf("cpu%u: %s\n", cpu->id, cpu->model_name);
    }

    if ((cpu->phys_addr_width != 0) && (cpu->virt_addr_width != 0)) {
        printf("cpu%u: address widths: physical: %hu, virtual: %hu\n",
               cpu->id, cpu->phys_addr_width, cpu->virt_addr_width);
    }
}

void __init
cpu_mp_register_lapic(unsigned int apic_id, int is_bsp)
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
    cpu_preinit(cpu, cpu_nr_active, apic_id);
    cpu_nr_active++;
}

void __init
cpu_mp_probe(void)
{
    int error;

    error = acpimp_setup();

    /* TODO Support UP with legacy PIC */
    if (error) {
        panic("cpu: ACPI required to initialize local APIC");
    }

    printf("cpu: %u processor(s) configured\n", cpu_count());
}

void __init
cpu_mp_setup(void)
{
    struct vm_page *page;
    uint16_t reset_vector[2];
    struct cpu *cpu;
    unsigned int i;
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

    for (i = 1; i < cpu_count(); i++) {
        cpu = percpu_ptr(cpu_desc, i);
        page = vm_page_alloc(vm_page_order(STACK_SIZE), VM_PAGE_SEL_DIRECTMAP,
                             VM_PAGE_KERNEL);

        if (page == NULL) {
            panic("cpu: unable to allocate boot stack for cpu%u", i);
        }

        cpu->boot_stack = vm_page_direct_ptr(page);
        page = vm_page_alloc(vm_page_order(STACK_SIZE), VM_PAGE_SEL_DIRECTMAP,
                             VM_PAGE_KERNEL);

        if (page == NULL) {
            panic("cpu: unable to allocate double fault stack for cpu%u", i);
        }

        cpu->double_fault_stack = vm_page_direct_ptr(page);
    }

    /*
     * This function creates per-CPU copies of the page tables. Just in case,
     * call it last to make sure all processors get the same mappings.
     */
    pmap_mp_setup();

    for (i = 1; i < cpu_count(); i++) {
        cpu = percpu_ptr(cpu_desc, i);
        boot_ap_id = i;

        /* Perform the "Universal Start-up Algorithm" */
        lapic_ipi_init_assert(cpu->apic_id);
        cpu_delay(200);
        lapic_ipi_init_deassert(cpu->apic_id);
        cpu_delay(10000);
        lapic_ipi_startup(cpu->apic_id, BOOT_MP_TRAMPOLINE_ADDR >> 12);
        cpu_delay(200);
        lapic_ipi_startup(cpu->apic_id, BOOT_MP_TRAMPOLINE_ADDR >> 12);
        cpu_delay(200);

        while (cpu->state == CPU_STATE_OFF) {
            cpu_pause();
        }
    }
}

void __init
cpu_ap_setup(void)
{
    struct cpu *cpu;

    cpu = percpu_ptr(cpu_desc, boot_ap_id);
    cpu_init(cpu);
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

    lapic_ipi_broadcast(TRAP_CPU_HALT);
}

void
cpu_halt_intr(struct trap_frame *frame)
{
    (void)frame;

    lapic_eoi();

    cpu_halt();
}

void
cpu_xcall_intr(struct trap_frame *frame)
{
    (void)frame;

    lapic_eoi();

    xcall_intr();
}

void
cpu_thread_schedule_intr(struct trap_frame *frame)
{
    (void)frame;

    lapic_eoi();

    thread_schedule_intr();
}
