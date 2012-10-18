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

#ifndef _X86_CPU_H
#define _X86_CPU_H

/*
 * GDT segment selectors.
 */
#define CPU_GDT_SEL_NULL    0
#define CPU_GDT_SEL_CODE    8
#define CPU_GDT_SEL_DATA    16

#ifdef __LP64__
#define CPU_GDT_SIZE        24
#else /* __LP64__ */
#define CPU_GDT_SEL_CPU     24
#define CPU_GDT_SIZE        32
#endif /* __LP64__ */

/*
 * Control register 0 flags.
 */
#define CPU_CR0_PE  0x00000001
#define CPU_CR0_MP  0x00000002
#define CPU_CR0_TS  0x00000008
#define CPU_CR0_ET  0x00000010
#define CPU_CR0_NE  0x00000020
#define CPU_CR0_WP  0x00010000
#define CPU_CR0_AM  0x00040000
#define CPU_CR0_PG  0x80000000

/*
 * Control register 4 flags.
 */
#define CPU_CR4_PAE 0x00000020
#define CPU_CR4_PGE 0x00000080

/*
 * EFLAGS register flags.
 */
#define CPU_EFL_ONE 0x00000002
#define CPU_EFL_IF  0x00000200

/*
 * Flags in the feature2 member.
 */
#define CPU_FEATURE2_FPU    0x00000001
#define CPU_FEATURE2_MSR    0x00000020
#define CPU_FEATURE2_APIC   0x00000200
#define CPU_FEATURE2_PGE    0x00002000

#define CPU_FEATURE4_LM     0x20000000

/*
 * Model specific registers.
 */
#define CPU_MSR_EFER    0xc0000080
#define CPU_MSR_FSBASE  0xc0000100

/*
 * EFER MSR flags.
 */
#define CPU_EFER_LME    0x00000100

#ifndef __ASSEMBLY__

#include <kern/param.h>
#include <lib/macros.h>
#include <lib/stddef.h>
#include <lib/stdint.h>
#include <machine/pit.h>

#define CPU_VENDOR_ID_SIZE  13
#define CPU_MODEL_NAME_SIZE 49

struct cpu_pseudo_desc {
    uint16_t limit;
    unsigned long address;
} __packed;

/*
 * Gate/segment descriptor bits and masks.
 */
#define CPU_DESC_TYPE_DATA              0x00000200
#define CPU_DESC_TYPE_CODE              0x00000a00
#define CPU_DESC_TYPE_GATE_INTR         0x00000e00
#define CPU_DESC_TYPE_GATE_TRAP         0x00000f00
#define CPU_DESC_S                      0x00001000
#define CPU_DESC_PRESENT                0x00008000
#define CPU_DESC_LONG                   0x00200000
#define CPU_DESC_DB                     0x00400000
#define CPU_DESC_GRAN_4KB               0x00800000

#define CPU_DESC_GATE_OFFSET_LOW_MASK   0x0000ffff
#define CPU_DESC_GATE_OFFSET_HIGH_MASK  0xffff0000
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
} __packed;

/*
 * Code or data segment descriptor.
 */
struct cpu_seg_desc {
    uint32_t low;
    uint32_t high;
} __packed;

/*
 * CPU states.
 */
#define CPU_STATE_OFF   0
#define CPU_STATE_ON    1

/*
 * The fs segment register is used to store the address of the per-cpu data.
 * As a result, they must be at least 16-bytes aligned.
 */
#define CPU_ALIGN (MAX(16, CPU_L1_SIZE))

struct cpu {
    struct cpu *self;
    unsigned int id;
    unsigned int apic_id;
    char vendor_id[CPU_VENDOR_ID_SIZE];
    char model_name[CPU_MODEL_NAME_SIZE];
    unsigned int type;
    unsigned int family;
    unsigned int model;
    unsigned int stepping;
    unsigned int clflush_size;
    unsigned int initial_apic_id;
    unsigned int features1;
    unsigned int features2;
    unsigned int features3;
    unsigned int features4;
    char gdt[CPU_GDT_SIZE] __aligned(8);
    volatile int state;
    unsigned long boot_stack;
} __aligned(CPU_ALIGN);

extern struct cpu cpu_array[MAX_CPUS];

/*
 * Macro to create functions that read/write registers.
 */
#define CPU_DECL_GETSET_REGISTER(name)                              \
static __always_inline unsigned long                                \
cpu_get_ ## name(void)                                              \
{                                                                   \
    unsigned long name;                                             \
                                                                    \
    asm volatile("mov %%" __QUOTE(name) ", %0" : "=r" (name));      \
    return name;                                                    \
}                                                                   \
                                                                    \
static __always_inline void                                         \
cpu_set_ ## name(unsigned long value)                               \
{                                                                   \
    asm volatile("mov %0, %%" __QUOTE(name) : : "r" (value));       \
}

/*
 * Access to the processor control registers. CR1 is reserved.
 */
CPU_DECL_GETSET_REGISTER(cr0)
CPU_DECL_GETSET_REGISTER(cr2)
CPU_DECL_GETSET_REGISTER(cr3)
CPU_DECL_GETSET_REGISTER(cr4)

/*
 * Flush the whole TLB.
 */
static __always_inline void
cpu_tlb_flush(void)
{
    cpu_set_cr3(cpu_get_cr3());
}

/*
 * Flush a single page table entry in the TLB. In some cases, the entire TLB
 * can be flushed by this instruction. The va parameter is a virtual
 * address in the page described by the PTE to flush.
 */
static __always_inline void
cpu_tlb_flush_va(unsigned long va)
{
    asm volatile("invlpg (%0)" : : "r" (va) : "memory");
}

/*
 * Return the content of the EFLAGS register.
 */
static __always_inline unsigned long
cpu_get_flags(void)
{
    unsigned long flags;

    asm volatile("pushf\n"
                 "pop %0\n"
                 : "=r" (flags));

    return flags;
}

/*
 * Enable local interrupts.
 */
static __always_inline void
cpu_intr_enable(void)
{
    asm volatile("sti");
}

/*
 * Disable local interrupts.
 */
static __always_inline void
cpu_intr_disable(void)
{
    asm volatile("cli");
}

/*
 * Restore the content of the EFLAGS register, possibly enabling interrupts.
 */
static __always_inline void
cpu_intr_restore(unsigned long flags)
{
    asm volatile("push %0\n"
                 "popf\n"
                 : : "r" (flags));
}

/*
 * Disable local interrupts, returning the previous content of the EFLAGS
 * register.
 */
static __always_inline unsigned long
cpu_intr_save(void)
{
    unsigned long flags;

    flags = cpu_get_flags();
    cpu_intr_disable();

    return flags;
}

/*
 * Return true if interrupts are enabled.
 */
static __always_inline int
cpu_intr_enabled(void)
{
    unsigned long flags;

    flags = cpu_get_flags();
    return (flags & CPU_EFL_IF) ? 1 : 0;
}

/*
 * Spin-wait loop hint.
 */
static __always_inline void
cpu_pause(void)
{
    asm volatile("pause");
}

/*
 * Make the CPU idle until the next interrupt.
 */
static __always_inline void
cpu_idle(void)
{
    asm volatile("hlt");
}

/*
 * Halt the CPU.
 */
static __noreturn __always_inline void
cpu_halt(void)
{
    cpu_intr_disable();

    for (;;)
        cpu_idle();
}

static __always_inline struct cpu *
cpu_current(void)
{
    struct cpu *cpu;

    asm volatile("mov %%fs:%1, %0"
                 : "=r" (cpu)
                 : "m" (*(struct cpu *)offsetof(struct cpu, self)));

    return cpu;
}

static __always_inline unsigned int
cpu_id(void)
{
    return cpu_current()->id;
}

static __always_inline void
cpu_enable_pae(void)
{
    cpu_set_cr4(cpu_get_cr4() | CPU_CR4_PAE);
}

static __always_inline int
cpu_has_global_pages(void)
{
    return cpu_current()->features2 & CPU_FEATURE2_PGE;
}

static __always_inline void
cpu_enable_global_pages(void)
{
    cpu_set_cr4(cpu_get_cr4() | CPU_CR4_PGE);
}

static __always_inline void
cpu_get_msr(uint32_t msr, uint32_t *low, uint32_t *high)
{
    asm volatile("rdmsr" : "=a" (*low), "=d" (*high) : "c" (msr));
}

static __always_inline void
cpu_set_msr(uint32_t msr, uint32_t low, uint32_t high)
{
    asm volatile("wrmsr" : : "c" (msr), "a" (low), "d" (high));
}

/*
 * XXX For now, directly use the PIT.
 */
static __always_inline void
cpu_delay(unsigned long usecs)
{
    pit_delay(usecs);
}

/*
 * Set the given GDT for the current processor, and reload its segment
 * registers.
 */
void cpu_load_gdt(struct cpu *cpu, struct cpu_pseudo_desc *gdtr);

/*
 * Set up the cpu module.
 */
void cpu_setup(void);

/*
 * Make sure the CPU has some required features.
 */
void cpu_check(const struct cpu *cpu);

/*
 * Display processor information.
 */
void cpu_info(const struct cpu *cpu);

/*
 * Register the presence of a local APIC.
 */
void cpu_mp_register_lapic(unsigned int apic_id, int is_bsp);

/*
 * Probe application processors and start them.
 */
void cpu_mp_setup(void);

/*
 * AP-specific functions.
 */
void cpu_ap_setup(void);

/*
 * Trap functions.
 */
void cpu_trap_default(void);
void cpu_trap_lapic_timer_intr(void);
void cpu_trap_lapic_spurious_intr(void);

#endif /* __ASSEMBLY__ */

#endif /* _X86_CPU_H */
