/*
 * Copyright (c) 2010, 2011, 2012 Richard Braun.
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
#include <kern/panic.h>
#include <kern/param.h>
#include <kern/printk.h>
#include <lib/assert.h>
#include <lib/macros.h>
#include <lib/stddef.h>
#include <lib/stdint.h>
#include <lib/string.h>
#include <machine/acpimp.h>
#include <machine/biosmem.h>
#include <machine/boot.h>
#include <machine/cpu.h>
#include <machine/io.h>
#include <machine/lapic.h>
#include <machine/trap.h>
#include <vm/vm_kmem.h>
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

struct cpu cpu_array[MAX_CPUS];

/*
 * Number of configured processors.
 */
static unsigned int cpu_array_size;

/*
 * Interrupt descriptor table.
 */
static struct cpu_gate_desc cpu_idt[CPU_IDT_SIZE] __aligned(8);

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

static void __init
cpu_init_gdt(struct cpu *cpu)
{
    struct cpu_pseudo_desc gdtr;

    cpu_seg_set_null(cpu->gdt, CPU_GDT_SEL_NULL);
    cpu_seg_set_code(cpu->gdt, CPU_GDT_SEL_CODE);
    cpu_seg_set_data(cpu->gdt, CPU_GDT_SEL_DATA, 0);

#ifndef __LP64__
    cpu_seg_set_data(cpu->gdt, CPU_GDT_SEL_CPU, (unsigned long)cpu);
#endif /* __LP64__ */

    gdtr.address = (unsigned long)cpu->gdt;
    gdtr.limit = sizeof(cpu->gdt) - 1;
    cpu_load_gdt(cpu, &gdtr);
}

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

static void
cpu_load_idt(void)
{
    static volatile struct cpu_pseudo_desc idtr;

    idtr.address = (unsigned long)cpu_idt;
    idtr.limit = sizeof(cpu_idt) - 1;
    asm volatile("lidt %0" : : "m" (idtr));
}

static __always_inline void
cpu_cpuid(unsigned long *eax, unsigned long *ebx, unsigned long *ecx,
          unsigned long *edx)
{
    asm volatile("cpuid" : "+a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx));
}

/*
 * Initialize the given cpu structure for the current processor.
 *
 * On the BSP, this function is called before it can determine the cpu
 * structure. It is part of its task to make it possible.
 */
static void __init
cpu_init(struct cpu *cpu)
{
    unsigned long eax, ebx, ecx, edx, max_basic, max_extended;

    /*
     * Assume at least an i586 processor.
     */

    cpu_intr_restore(CPU_EFL_ONE);
    cpu_set_cr0(CPU_CR0_PG | CPU_CR0_AM | CPU_CR0_WP | CPU_CR0_NE | CPU_CR0_ET
                | CPU_CR0_TS | CPU_CR0_MP | CPU_CR0_PE);
    cpu_init_gdt(cpu);
    cpu_load_idt();

    eax = 0;
    cpu_cpuid(&eax, &ebx, &ecx, &edx);
    max_basic = eax;
    memcpy(cpu->vendor_id, &ebx, sizeof(ebx));
    memcpy(cpu->vendor_id + 4, &edx, sizeof(edx));
    memcpy(cpu->vendor_id + 8, &ecx, sizeof(ecx));
    cpu->vendor_id[sizeof(cpu->vendor_id) - 1] = '\0';

    /* Initialized if the processor supports brand strings */
    cpu->model_name[0] = '\0';

    assert(max_basic >= 1);

    eax = 1;
    cpu_cpuid(&eax, &ebx, &ecx, &edx);
    cpu->type = (eax & CPU_TYPE_MASK) >> CPU_TYPE_SHIFT;
    cpu->family = (eax & CPU_FAMILY_MASK) >> CPU_FAMILY_SHIFT;

    if (cpu->family == 0xf)
        cpu->family += (eax & CPU_EXTFAMILY_MASK) >> CPU_EXTFAMILY_SHIFT;

    cpu->model = (eax & CPU_MODEL_MASK) >> CPU_MODEL_SHIFT;

    if ((cpu->model == 6) || (cpu->model == 0xf))
        cpu->model += (eax & CPU_EXTMODEL_MASK) >> CPU_EXTMODEL_SHIFT;

    cpu->stepping = (eax & CPU_STEPPING_MASK) >> CPU_STEPPING_SHIFT;
    cpu->clflush_size = ((ebx & CPU_CLFLUSH_MASK) >> CPU_CLFLUSH_SHIFT) * 8;
    cpu->initial_apic_id = (ebx & CPU_APIC_ID_MASK) >> CPU_APIC_ID_SHIFT;
    cpu->features1 = ecx;
    cpu->features2 = edx;

    eax = 0x80000000;
    cpu_cpuid(&eax, &ebx, &ecx, &edx);

    if (eax <= 0x80000000)
        max_extended = 0;
    else
        max_extended = eax;

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

    cpu->state = CPU_STATE_ON;
}

void __init
cpu_setup(void)
{
    size_t i;

    for (i = 0; i < ARRAY_SIZE(cpu_array); i++) {
        cpu_array[i].self = &cpu_array[i];
        cpu_array[i].id = i;
        cpu_array[i].apic_id = CPU_INVALID_APIC_ID;
        cpu_array[i].state = CPU_STATE_OFF;
    }

    cpu_array_size = 1;
    cpu_init(&cpu_array[0]);
}

static void __init
cpu_panic_on_missing_feature(const char *feature)
{
    panic("cpu: %s feature missing", feature);
}

void __init
cpu_check(const struct cpu *cpu)
{
    if (!(cpu->features2 & CPU_FEATURE2_FPU))
        cpu_panic_on_missing_feature("fpu");

    /* TODO: support UP with legacy PIC machines */
    if (!(cpu->features2 & CPU_FEATURE2_APIC))
        cpu_panic_on_missing_feature("apic");
}

void
cpu_info(const struct cpu *cpu)
{
    printk("cpu%u: %s, type %u, family %u, model %u, stepping %u\n",
           cpu->id, cpu->vendor_id, cpu->type, cpu->family, cpu->model,
           cpu->stepping);

    if (strlen(cpu->model_name) > 0)
        printk("cpu%u: %s\n", cpu->id, cpu->model_name);
}

void __init
cpu_mp_register_lapic(unsigned int apic_id, int is_bsp)
{
    if (is_bsp) {
        if (cpu_array[0].apic_id != CPU_INVALID_APIC_ID)
            panic("cpu: another processor pretends to be the BSP");

        cpu_array[0].apic_id = apic_id;
        return;
    }

    if (cpu_array_size == ARRAY_SIZE(cpu_array)) {
        printk("cpu: ignoring processor beyond id %u\n", MAX_CPUS - 1);
        return;
    }

    cpu_array[cpu_array_size].apic_id = apic_id;
    cpu_array_size++;
}

static void __init
cpu_mp_start_aps(void)
{
    uint16_t reset_vector[2];
    struct cpu *cpu;
    void *ptr;
    unsigned long map_addr;
    size_t map_size;
    unsigned int i;

    if (cpu_array_size == 1)
        return;

    assert(BOOT_MP_TRAMPOLINE_ADDR < BIOSMEM_BASE);
    assert(vm_page_aligned(BOOT_MP_TRAMPOLINE_ADDR));
    assert(boot_mp_trampoline_size <= PAGE_SIZE);

    /* Set up the AP trampoline code */
    ptr = vm_kmem_map_pa(BOOT_MP_TRAMPOLINE_ADDR, boot_mp_trampoline_size,
                         &map_addr, &map_size);

    if (ptr == NULL)
        panic("cpu: unable to map trampoline area in kernel map");

    memcpy(ptr, boot_mp_trampoline, boot_mp_trampoline_size);
    vm_kmem_unmap_pa(map_addr, map_size);

    /* Set up the warm reset vector */
    reset_vector[0] = 0;
    reset_vector[1] = BOOT_MP_TRAMPOLINE_ADDR >> 4;
    ptr = vm_kmem_map_pa(CPU_MP_CMOS_RESET_VECTOR, sizeof(reset_vector),
                         &map_addr, &map_size);

    if (ptr == NULL)
        panic("cpu: unable to map warm reset vector in kernel map");

    memcpy(ptr, reset_vector, sizeof(reset_vector));
    vm_kmem_unmap_pa(map_addr, map_size);

    io_write_byte(CPU_MP_CMOS_PORT_REG, CPU_MP_CMOS_REG_RESET);
    io_write_byte(CPU_MP_CMOS_PORT_DATA, CPU_MP_CMOS_DATA_RESET_WARM);

    /* Perform the "Universal Start-up Algorithm" */
    for (i = 1; i < cpu_array_size; i++) {
        cpu = &cpu_array[i];

        cpu->boot_stack = vm_kmem_alloc(BOOT_STACK_SIZE);

        if (cpu->boot_stack == 0)
            panic("unable to allocate boot stack for cpu%u", i);

        boot_ap_id = i;
        boot_ap_stack_addr = cpu->boot_stack;

        lapic_ipi_init_assert(cpu->apic_id);
        cpu_delay(200);
        lapic_ipi_init_deassert(cpu->apic_id);
        cpu_delay(10000);
        lapic_ipi_startup(cpu->apic_id, BOOT_MP_TRAMPOLINE_ADDR >> 12);
        cpu_delay(200);
        lapic_ipi_startup(cpu->apic_id, BOOT_MP_TRAMPOLINE_ADDR >> 12);
        cpu_delay(200);

        while (cpu->state == CPU_STATE_OFF)
            cpu_pause();
    }
}

static void __init
cpu_mp_info(void)
{
    printk("cpu: %u processor(s) configured\n", cpu_array_size);
}

void __init
cpu_mp_setup(void)
{
    acpimp_setup();
    cpu_mp_start_aps();
    cpu_mp_info();
}

void __init
cpu_ap_setup(void)
{
    cpu_init(&cpu_array[boot_ap_id]);
    cpu_check(cpu_current());
    lapic_ap_setup();
}
