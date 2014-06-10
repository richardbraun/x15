/*
 * Copyright (c) 2010-2014 Richard Braun.
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
#define CPU_GDT_SEL_TSS     24

#ifdef __LP64__
#define CPU_GDT_SIZE        40
#else /* __LP64__ */
#define CPU_GDT_SEL_DF_TSS  32
#define CPU_GDT_SEL_CPU     40
#define CPU_GDT_SIZE        48
#endif /* __LP64__ */

#define CPU_IDT_SIZE 256

/*
 * Processor privilege levels.
 */
#define CPU_PL_KERNEL   0
#define CPU_PL_USER     3

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

#ifndef __ASSEMBLER__

#include <kern/assert.h>
#include <kern/macros.h>
#include <kern/param.h>
#include <kern/stddef.h>
#include <kern/stdint.h>
#include <machine/lapic.h>
#include <machine/pit.h>

/*
 * Forward declaration.
 */
struct trap_frame;

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
} __packed;

/*
 * Code or data segment descriptor.
 */
struct cpu_seg_desc {
    uint32_t low;
    uint32_t high;
} __packed;

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
} __packed;

/*
 * IST indexes (0 is reserved).
 */
#define CPU_TSS_IST_DF 1

struct cpu_tss {
#ifdef __LP64__
    uint32_t reserved0;
    uint64_t rsp0;
    uint64_t rsp1;
    uint64_t rsp2;
    uint64_t ist[8];
    uint64_t reserved1;
    uint16_t reserved2;
#else /* __LP64__ */
    uint32_t link;
    uint32_t esp0;
    uint32_t ss0;
    uint32_t esp1;
    uint32_t ss1;
    uint32_t esp2;
    uint32_t ss2;
    uint32_t cr3;
    uint32_t eip;
    uint32_t eflags;
    uint32_t eax;
    uint32_t ecx;
    uint32_t edx;
    uint32_t ebx;
    uint32_t esp;
    uint32_t ebp;
    uint32_t esi;
    uint32_t edi;
    uint32_t es;
    uint32_t cs;
    uint32_t ss;
    uint32_t ds;
    uint32_t fs;
    uint32_t gs;
    uint32_t ldt;
    uint16_t trap_bit;
#endif /* __LP64__ */
    uint16_t iobp_base;
} __packed;

/*
 * Forward declarations.
 */
struct tcb;
struct pmap;

/*
 * CPU states.
 */
#define CPU_STATE_OFF   0
#define CPU_STATE_ON    1

/*
 * The fs segment register is used to store the address of the per-CPU data.
 * As a result, they must be at least 16-bytes aligned.
 */
#define CPU_ALIGN (MAX(16, CPU_L1_SIZE))

struct cpu {
    struct cpu *self;
    struct tcb *tcb;
    struct pmap *pmap;
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
    unsigned short phys_addr_width;
    unsigned short virt_addr_width;
    char gdt[CPU_GDT_SIZE] __aligned(8);
    struct cpu_tss tss;
#ifndef __LP64__
    struct cpu_tss double_fault_tss;
#endif /* __LP64__ */
    volatile int state;
    unsigned long boot_stack;
    unsigned long double_fault_stack;
} __aligned(CPU_ALIGN);

/*
 * Macro to create functions that read/write control registers.
 */
#define CPU_DECL_GETSET_CR(name)                                            \
static __always_inline unsigned long                                        \
cpu_get_ ## name(void)                                                      \
{                                                                           \
    unsigned long name;                                                     \
                                                                            \
    asm volatile("mov %%" __QUOTE(name) ", %0" : "=r" (name) : : "memory"); \
    return name;                                                            \
}                                                                           \
                                                                            \
static __always_inline void                                                 \
cpu_set_ ## name(unsigned long value)                                       \
{                                                                           \
    asm volatile("mov %0, %%" __QUOTE(name) : : "r" (value) : "memory");    \
}

/*
 * Access to the processor control registers. CR1 is reserved.
 *
 * Implies a compiler barrier.
 */
CPU_DECL_GETSET_CR(cr0)
CPU_DECL_GETSET_CR(cr2)
CPU_DECL_GETSET_CR(cr3)
CPU_DECL_GETSET_CR(cr4)

/*
 * Return the content of the EFLAGS register.
 *
 * Implies a compiler barrier.
 */
static __always_inline unsigned long
cpu_get_eflags(void)
{
    unsigned long eflags;

    asm volatile("pushf\n"
                 "pop %0\n"
                 : "=r" (eflags)
                 : : "memory");

    return eflags;
}

/*
 * Enable local interrupts.
 *
 * Implies a compiler barrier.
 */
static __always_inline void
cpu_intr_enable(void)
{
    asm volatile("sti" : : : "memory");
}

/*
 * Disable local interrupts.
 *
 * Implies a compiler barrier.
 */
static __always_inline void
cpu_intr_disable(void)
{
    asm volatile("cli" : : : "memory");
}

/*
 * Restore the content of the EFLAGS register, possibly enabling interrupts.
 *
 * Implies a compiler barrier.
 */
static __always_inline void
cpu_intr_restore(unsigned long eflags)
{
    asm volatile("push %0\n"
                 "popf\n"
                 : : "r" (eflags)
                 : "memory");
}

/*
 * Disable local interrupts, returning the previous content of the EFLAGS
 * register.
 *
 * Implies a compiler barrier.
 */
static __always_inline void
cpu_intr_save(unsigned long *eflags)
{
    *eflags = cpu_get_eflags();
    cpu_intr_disable();
}

/*
 * Return true if interrupts are enabled.
 *
 * Implies a compiler barrier.
 */
static __always_inline int
cpu_intr_enabled(void)
{
    unsigned long eflags;

    eflags = cpu_get_eflags();
    return (eflags & CPU_EFL_IF) ? 1 : 0;
}

/*
 * Spin-wait loop hint.
 *
 * Implies a compiler barrier.
 */
static __always_inline void
cpu_pause(void)
{
    asm volatile("pause" : : : "memory");
}

/*
 * Make the CPU idle until the next interrupt.
 *
 * Interrupts are enabled. Besides, they're enabled in a way that doesn't
 * allow the processor handling them before entering the idle state if they
 * were disabled before calling this function.
 *
 * Implies a compiler barrier.
 */
static __always_inline void
cpu_idle(void)
{
    asm volatile("sti; hlt" : : : "memory");
}

/*
 * Halt the CPU.
 *
 * Implies a compiler barrier.
 */
static __noreturn __always_inline void
cpu_halt(void)
{
    cpu_intr_disable();

    for (;;)
        asm volatile("hlt" : : : "memory");
}

/*
 * Halt all other processors.
 *
 * Interrupts must be disabled when calling this function.
 */
void cpu_halt_broadcast(void);

/*
 * Interrupt handler for inter-processor halt requests.
 */
void cpu_halt_intr(struct trap_frame *frame);

/*
 * Macros to create access functions for per-CPU pointers.
 *
 * Changing such a pointer should only be done by low level scheduling
 * functions (e.g. context switching). Getting it is then migration-safe.
 */
#ifdef __LP64__
#define CPU_ASM_MOV "movq"
#else /* __LP64__ */
#define CPU_ASM_MOV "movl"
#endif /* __LP64__ */

#define CPU_DECL_PERCPU(type, member)                               \
static __always_inline type *                                       \
cpu_percpu_get_ ## member(void)                                     \
{                                                                   \
    type *ptr;                                                      \
                                                                    \
    asm volatile(CPU_ASM_MOV " %%fs:%1, %0"                         \
                 : "=r" (ptr)                                       \
                 : "m" (*(type **)offsetof(struct cpu, member)));   \
    return ptr;                                                     \
}                                                                   \
                                                                    \
static __always_inline void                                         \
cpu_percpu_set_ ## member(type *ptr)                                \
{                                                                   \
    asm volatile(CPU_ASM_MOV " %0, %%fs:%1"                         \
                 : : "ri" (ptr),                                    \
                     "m" (*(type **)offsetof(struct cpu, member))); \
}

CPU_DECL_PERCPU(struct cpu, self)
CPU_DECL_PERCPU(struct tcb, tcb)
CPU_DECL_PERCPU(struct pmap, pmap)

static __always_inline struct cpu *
cpu_current(void)
{
    return cpu_percpu_get_self();
}

static __always_inline unsigned int
cpu_id(void)
{
    unsigned int id;

    asm volatile("movl %%fs:%1, %0"
                 : "=r" (id)
                 : "m" (*(unsigned int *)offsetof(struct cpu, id)));
    return id;
}

static __always_inline unsigned int
cpu_count(void)
{
    extern unsigned int cpu_array_size;
    return cpu_array_size;
}

static inline struct cpu *
cpu_from_id(unsigned int cpu)
{
    extern struct cpu cpu_array[MAX_CPUS];
    assert(cpu < ARRAY_SIZE(cpu_array));
    return &cpu_array[cpu];
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

/*
 * Enable the use of global pages in the TLB.
 *
 * As a side effect, this function causes a complete TLB flush if global
 * pages were previously disabled.
 *
 * Implies a full memory barrier.
 */
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
 * Flush non-global TLB entries.
 *
 * Implies a full memory barrier.
 */
static __always_inline void
cpu_tlb_flush(void)
{
    cpu_set_cr3(cpu_get_cr3());
}

/*
 * Flush all TLB entries, including global ones.
 *
 * Implies a full memory barrier.
 */
static __always_inline void
cpu_tlb_flush_all(void)
{
    if (!cpu_has_global_pages())
        cpu_tlb_flush();
    else {
        unsigned long cr4;

        cr4 = cpu_get_cr4();

        if (!(cr4 & CPU_CR4_PGE))
            cpu_tlb_flush();
        else {
            cr4 &= ~CPU_CR4_PGE;
            cpu_set_cr4(cr4);
            cr4 |= CPU_CR4_PGE;
            cpu_set_cr4(cr4);
        }
    }
}

/*
 * Flush a single page table entry in the TLB.
 *
 * Implies a full memory barrier.
 */
static __always_inline void
cpu_tlb_flush_va(unsigned long va)
{
    asm volatile("invlpg (%0)" : : "r" (va) : "memory");
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
 * Return the address of the boot stack allocated for the current processor.
 */
unsigned long cpu_get_boot_stack(void);

/*
 * Set the given GDT for the current processor, and reload its segment
 * registers.
 */
void cpu_load_gdt(struct cpu *cpu, struct cpu_pseudo_desc *gdtr);

/*
 * Install an interrupt handler in the IDT.
 */
void cpu_idt_set_gate(unsigned int vector, void (*isr)(void));
void cpu_idt_set_double_fault(void (*isr)(void));

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
 *
 * On return, cpu_count() gives the actual number of managed processors.
 */
void cpu_mp_probe(void);

/*
 * Start application processors.
 *
 * The x86 architecture uses per-CPU page tables, which are created as a
 * side effect of this function. In order to synchronize their page tables,
 * processors must be able to communicate very soon after calling this
 * function. They communicate through interrupts and threading facilities.
 * On return, physical mappings must not be altered until inter-processor
 * communication is available.
 */
void cpu_mp_setup(void);

/*
 * CPU initialization on APs.
 */
void cpu_ap_setup(void);

/*
 * Send a scheduling interrupt to a remote processor.
 */
static inline void
cpu_send_thread_schedule(unsigned int cpu)
{
    lapic_ipi_send(cpu_from_id(cpu)->apic_id, TRAP_THREAD_SCHEDULE);
}

/*
 * Interrupt handler for scheduling requests.
 */
void cpu_thread_schedule_intr(struct trap_frame *frame);

#endif /* __ASSEMBLER__ */

#endif /* _X86_CPU_H */
