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

#ifndef _X86_CPU_H
#define _X86_CPU_H

#include <limits.h>

/*
 * L1 cache line size.
 *
 * XXX Use this value until processor selection is available.
 */
#define CPU_L1_SIZE 64

/*
 * Data alignment, normally the word size.
 */
#define CPU_DATA_ALIGN (LONG_BIT / 8)

/*
 * Function alignment.
 *
 * Aligning functions improves instruction fetching.
 *
 * Used for assembly functions only.
 *
 * XXX Use this value until processor selection is available.
 */
#define CPU_TEXT_ALIGN 16

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
#define CPU_CR4_PSE 0x00000010
#define CPU_CR4_PAE 0x00000020
#define CPU_CR4_PGE 0x00000080

/*
 * EFLAGS register flags.
 */
#define CPU_EFL_ONE 0x00000002  /* Reserved, must be one */
#define CPU_EFL_IF  0x00000200

/*
 * Model specific registers.
 */
#define CPU_MSR_EFER    0xc0000080
#define CPU_MSR_FSBASE  0xc0000100
#define CPU_MSR_GSBASE  0xc0000101

/*
 * EFER MSR flags.
 */
#define CPU_EFER_LME    0x00000100

/*
 * Feature2 flags.
 *
 * TODO Better names.
 */
#define CPU_FEATURE2_FPU    0x00000001
#define CPU_FEATURE2_PSE    0x00000008
#define CPU_FEATURE2_PAE    0x00000040
#define CPU_FEATURE2_MSR    0x00000020
#define CPU_FEATURE2_CX8    0x00000100
#define CPU_FEATURE2_APIC   0x00000200
#define CPU_FEATURE2_PGE    0x00002000

#define CPU_FEATURE4_1GP    0x04000000
#define CPU_FEATURE4_LM     0x20000000

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
#define CPU_GDT_SEL_PERCPU  40
#define CPU_GDT_SEL_TLS     48
#define CPU_GDT_SIZE        56
#endif /* __LP64__ */

#define CPU_IDT_SIZE 256

#ifndef __ASSEMBLER__

#include <stdalign.h>
#include <stdint.h>
#include <stdnoreturn.h>

#include <kern/init.h>
#include <kern/macros.h>
#include <kern/percpu.h>
#include <machine/lapic.h>
#include <machine/pit.h>
#include <machine/ssp.h>

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
 * Code or data segment descriptor.
 */
struct cpu_seg_desc {
    uint32_t low;
    uint32_t high;
};

/*
 * Forward declaration.
 */
struct trap_frame;

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

#define CPU_VENDOR_ID_SIZE  13
#define CPU_MODEL_NAME_SIZE 49

/*
 * CPU states.
 */
#define CPU_STATE_OFF   0
#define CPU_STATE_ON    1

struct cpu {
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
    alignas(8) char gdt[CPU_GDT_SIZE];
    struct cpu_tss tss;
#ifndef __LP64__
    struct cpu_tss double_fault_tss;
#endif /* __LP64__ */
    volatile int state;
    void *boot_stack;
    void *double_fault_stack;
};

struct cpu_tls_seg {
    uintptr_t unused[SSP_WORD_TLS_OFFSET];
    uintptr_t ssp_guard_word;
};

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
 * The caller should assume that these functions are declared as :
 *  static inline unsigned long cpu_get_crX(void);
 *  static inline void cpu_set_crX(unsigned long);
 *
 * They all imply a compiler barrier.
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
cpu_intr_restore(unsigned long flags)
{
    asm volatile("push %0\n"
                 "popf\n"
                 : : "r" (flags)
                 : "memory");
}

/*
 * Disable local interrupts, returning the previous content of the EFLAGS
 * register.
 *
 * Implies a compiler barrier.
 */
static __always_inline void
cpu_intr_save(unsigned long *flags)
{
    *flags = cpu_get_eflags();
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
noreturn static __always_inline void
cpu_halt(void)
{
    cpu_intr_disable();

    for (;;) {
        asm volatile("hlt" : : : "memory");
    }
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
 * This percpu variable contains the address of the percpu area for the local
 * processor. This is normally the same value stored in the percpu module, but
 * it can be directly accessed through a segment register.
 */
extern void *cpu_local_area;

#define cpu_local_ptr(var)                  \
MACRO_BEGIN                                 \
    typeof(var) *___ptr = &(var);           \
                                            \
    asm volatile("add %%fs:%1, %0"          \
                 : "+r" (___ptr)            \
                 : "m" (cpu_local_area));   \
                                            \
    ___ptr;                                 \
MACRO_END

#define cpu_local_var(var) (*cpu_local_ptr(var))

/* Interrupt-safe percpu accessors for basic types */

#define cpu_local_assign(var, val)          \
    asm volatile("mov %0, %%fs:%1"          \
                 : : "r" (val), "m" (var));

#define cpu_local_read(var)         \
MACRO_BEGIN                         \
    typeof(var) ___val;             \
                                    \
    asm volatile("mov %%fs:%1, %0"  \
                 : "=r" (___val)    \
                 : "m" (var));      \
                                    \
    ___val;                         \
MACRO_END

static inline struct cpu *
cpu_current(void)
{
    extern struct cpu cpu_desc;
    return cpu_local_ptr(cpu_desc);
}

static inline unsigned int
cpu_id(void)
{
    extern struct cpu cpu_desc;
    return cpu_local_read(cpu_desc.id);
}

static inline unsigned int
cpu_count(void)
{
    extern unsigned int cpu_nr_active;
    return cpu_nr_active;
}

static inline struct cpu *
cpu_from_id(unsigned int cpu)
{
    extern struct cpu cpu_desc;
    return percpu_ptr(cpu_desc, cpu);
}

static __always_inline void
cpu_enable_pse(void)
{
    cpu_set_cr4(cpu_get_cr4() | CPU_CR4_PSE);
}

static __always_inline void
cpu_enable_pae(void)
{
    cpu_set_cr4(cpu_get_cr4() | CPU_CR4_PAE);
}

static inline int
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

/*
 * CPUID instruction wrapper.
 *
 * The CPUID instruction is a serializing instruction, implying a full
 * memory barrier.
 */
static __always_inline void
cpu_cpuid(unsigned int *eax, unsigned int *ebx, unsigned int *ecx,
          unsigned int *edx)
{
    asm volatile("cpuid" : "+a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)
                 : : "memory");
}

static __always_inline void
cpu_get_msr(uint32_t msr, uint32_t *high, uint32_t *low)
{
    asm volatile("rdmsr" : "=a" (*low), "=d" (*high) : "c" (msr));
}

static __always_inline void
cpu_set_msr(uint32_t msr, uint32_t high, uint32_t low)
{
    asm volatile("wrmsr" : : "c" (msr), "a" (low), "d" (high));
}

static __always_inline uint64_t
cpu_get_tsc(void)
{
    uint32_t high, low;

    asm volatile("rdtsc" : "=a" (low), "=d" (high));
    return ((uint64_t)high << 32) | low;
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
    if (!cpu_has_global_pages()) {
        cpu_tlb_flush();
    } else {
        unsigned long cr4;

        cr4 = cpu_get_cr4();

        if (!(cr4 & CPU_CR4_PGE)) {
            cpu_tlb_flush();
        } else {
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
 * Busy-wait for a given amount of time, in microseconds.
 */
void cpu_delay(unsigned long usecs);

/*
 * Return the address of the boot stack allocated for the current processor.
 */
void * cpu_get_boot_stack(void);

/*
 * Install an interrupt handler in the IDT.
 *
 * These functions may be called before the cpu module is initialized.
 */
void cpu_idt_set_gate(unsigned int vector, void (*isr)(void));
void cpu_idt_set_double_fault(void (*isr)(void));

/*
 * Log processor information.
 */
void cpu_log_info(const struct cpu *cpu);

/*
 * Register the presence of a local APIC.
 */
void cpu_mp_register_lapic(unsigned int apic_id, int is_bsp);

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

static inline unsigned int
cpu_apic_id(unsigned int cpu)
{
    return cpu_from_id(cpu)->apic_id;
}

/*
 * Send a cross-call interrupt to a remote processor.
 */
static inline void
cpu_send_xcall(unsigned int cpu)
{
    lapic_ipi_send(cpu_apic_id(cpu), TRAP_XCALL);
}

/*
 * Interrupt handler for cross-calls.
 */
void cpu_xcall_intr(struct trap_frame *frame);

/*
 * Send a scheduling interrupt to a remote processor.
 */
static inline void
cpu_send_thread_schedule(unsigned int cpu)
{
    lapic_ipi_send(cpu_apic_id(cpu), TRAP_THREAD_SCHEDULE);
}

/*
 * Interrupt handler for scheduling requests.
 */
void cpu_thread_schedule_intr(struct trap_frame *frame);

/*
 * This init operation provides :
 *  - initialization of the BSP structure.
 *  - cpu_delay()
 *  - cpu_local_ptr() and cpu_local_var()
 */
INIT_OP_DECLARE(cpu_setup);

/*
 * This init operation provides :
 *  - cpu_count()
 */
INIT_OP_DECLARE(cpu_mp_probe);

/*
 * This init operation provides :
 *  - cpu shutdown operations registered
 */
INIT_OP_DECLARE(cpu_setup_shutdown);

#endif /* __ASSEMBLER__ */

#endif /* _X86_CPU_H */
