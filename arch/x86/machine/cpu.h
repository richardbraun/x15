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

#ifndef X86_CPU_H
#define X86_CPU_H

#include <limits.h>

#include <machine/page.h>

/*
 * Architecture defined exception vectors.
 */
#define CPU_EXC_DE                  0   /* Divide Error */
#define CPU_EXC_DB                  1   /* Debug */
#define CPU_EXC_NMI                 2   /* NMI Interrupt */
#define CPU_EXC_BP                  3   /* Breakpoint */
#define CPU_EXC_OF                  4   /* Overflow */
#define CPU_EXC_BR                  5   /* BOUND Range Exceeded */
#define CPU_EXC_UD                  6   /* Undefined Opcode */
#define CPU_EXC_NM                  7   /* No Math Coprocessor */
#define CPU_EXC_DF                  8   /* Double Fault */
#define CPU_EXC_TS                  10  /* Invalid TSS */
#define CPU_EXC_NP                  11  /* Segment Not Present */
#define CPU_EXC_SS                  12  /* Stack-Segment Fault */
#define CPU_EXC_GP                  13  /* General Protection */
#define CPU_EXC_PF                  14  /* Page Fault */
#define CPU_EXC_MF                  16  /* Math Fault */
#define CPU_EXC_AC                  17  /* Alignment Check */
#define CPU_EXC_MC                  18  /* Machine Check */
#define CPU_EXC_XM                  19  /* SIMD Floating-Point Exception */

/*
 * Exception vectors used for external interrupts.
 */
#define CPU_EXC_INTR_FIRST          32
#define CPU_EXC_INTR_LAST           223

/*
 * System defined exception vectors.
 *
 * The local APIC assigns one priority every 16 vectors.
 */
#define CPU_EXC_XCALL               238
#define CPU_EXC_THREAD_SCHEDULE     239
#define CPU_EXC_HALT                240
#define CPU_EXC_LAPIC_PMC_OF        252
#define CPU_EXC_LAPIC_TIMER         253
#define CPU_EXC_LAPIC_ERROR         254
#define CPU_EXC_LAPIC_SPURIOUS      255

#define CPU_NR_EXC_VECTORS          256

#define CPU_INTR_STACK_SIZE PAGE_SIZE

#define CPU_VENDOR_STR_SIZE 13
#define CPU_MODEL_NAME_SIZE 49

#define CPU_VENDOR_UNKNOWN  0
#define CPU_VENDOR_INTEL    1
#define CPU_VENDOR_AMD      2

/*
 * L1 cache line size.
 *
 * XXX Use this value until processor selection is available.
 *
 * TODO Add macros to specifically align to the cache line size, and to
 * do so only in SMP configurations.
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
#define CPU_PL_KERNEL                           0
#define CPU_PL_USER                             3

/*
 * Control register 0 flags.
 */
#define CPU_CR0_PE                              0x00000001
#define CPU_CR0_MP                              0x00000002
#define CPU_CR0_TS                              0x00000008
#define CPU_CR0_ET                              0x00000010
#define CPU_CR0_NE                              0x00000020
#define CPU_CR0_WP                              0x00010000
#define CPU_CR0_AM                              0x00040000
#define CPU_CR0_PG                              0x80000000

/*
 * Control register 4 flags.
 */
#define CPU_CR4_PSE                             0x00000010
#define CPU_CR4_PAE                             0x00000020
#define CPU_CR4_PGE                             0x00000080

/*
 * Model specific registers.
 */
#define CPU_MSR_EFER                            0xc0000080
#define CPU_MSR_FSBASE                          0xc0000100
#define CPU_MSR_GSBASE                          0xc0000101

/*
 * EFER MSR flags.
 */
#define CPU_EFER_LME                            0x00000100

/*
 * Bit used to make extended CPUID requests.
 */
#define CPU_CPUID_EXT_BIT                       0x80000000

/*
 * CPU feature flags as returned by CPUID.
 */
#define CPU_CPUID_BASIC1_EDX_FPU                0x00000001
#define CPU_CPUID_BASIC1_EDX_PSE                0x00000008
#define CPU_CPUID_BASIC1_EDX_PAE                0x00000040
#define CPU_CPUID_BASIC1_EDX_MSR                0x00000020
#define CPU_CPUID_BASIC1_EDX_CX8                0x00000100
#define CPU_CPUID_BASIC1_EDX_APIC               0x00000200
#define CPU_CPUID_BASIC1_EDX_PGE                0x00002000
#define CPU_CPUID_EXT1_EDX_1GP                  0x04000000
#define CPU_CPUID_EXT1_EDX_LM                   0x20000000

#ifndef __ASSEMBLER__

enum cpu_feature {
    CPU_FEATURE_FPU,
    CPU_FEATURE_PSE,
    CPU_FEATURE_PAE,
    CPU_FEATURE_MSR,
    CPU_FEATURE_CX8,
    CPU_FEATURE_APIC,
    CPU_FEATURE_PGE,
    CPU_FEATURE_1GP,
    CPU_FEATURE_LM,
    CPU_NR_FEATURES
};

#endif /* __ASSEMBLER__ */

#include <machine/cpu_i.h>

#ifndef __ASSEMBLER__

#include <stdalign.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdnoreturn.h>

#include <kern/init.h>
#include <kern/macros.h>
#include <kern/percpu.h>
#include <machine/lapic.h>
#include <machine/pit.h>
#include <machine/ssp.h>

#define CPU_INTR_TABLE_SIZE (CPU_EXC_INTR_LAST - CPU_EXC_INTR_FIRST)

/*
 * Gate/segment descriptor bits and masks.
 */
#define CPU_DESC_TYPE_DATA                      0x00000200
#define CPU_DESC_TYPE_CODE                      0x00000a00
#define CPU_DESC_TYPE_TSS                       0x00000900
#define CPU_DESC_TYPE_GATE_INTR                 0x00000e00
#define CPU_DESC_TYPE_GATE_TASK                 0x00000500
#define CPU_DESC_S                              0x00001000
#define CPU_DESC_PRESENT                        0x00008000
#define CPU_DESC_LONG                           0x00200000
#define CPU_DESC_DB                             0x00400000
#define CPU_DESC_GRAN_4KB                       0x00800000

#define CPU_DESC_GATE_OFFSET_LOW_MASK           0x0000ffff
#define CPU_DESC_GATE_OFFSET_HIGH_MASK          0xffff0000
#define CPU_DESC_SEG_IST_MASK                   0x00000007
#define CPU_DESC_SEG_BASE_LOW_MASK              0x0000ffff
#define CPU_DESC_SEG_BASE_MID_MASK              0x00ff0000
#define CPU_DESC_SEG_BASE_HIGH_MASK             0xff000000
#define CPU_DESC_SEG_LIMIT_LOW_MASK             0x0000ffff
#define CPU_DESC_SEG_LIMIT_HIGH_MASK            0x000f0000

/*
 * Type for interrupt handler functions.
 */
typedef void (*cpu_intr_handler_fn_t)(unsigned int vector);

/*
 * TLS segment, as expected by the compiler.
 *
 * TLS isn't actually used inside the kernel. The current purpose of this
 * segment is to implement stack protection.
 *
 * This is a public structure, made available to the boot module so that
 * C code that runs early correctly works when built with stack protection.
 */
struct cpu_tls_seg {
    uintptr_t unused[SSP_WORD_TLS_OFFSET];
    uintptr_t ssp_guard_word;
};

/*
 * Code or data segment descriptor.
 *
 * See Intel 64 and IA-32 Architecture Software Developer's Manual,
 * Volume 3 System Programming Guide, 3.4.5 Segment Descriptors.
 */
struct cpu_seg_desc {
    uint32_t low;
    uint32_t high;
};

/*
 * Macro to create functions that read/write control registers.
 *
 * TODO Break down.
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

/* Generic percpu accessors */

#define cpu_local_ptr(var)                  \
MACRO_BEGIN                                 \
    typeof(var) *ptr_ = &(var);             \
                                            \
    asm("add %%fs:%1, %0"                   \
                 : "+r" (ptr_)              \
                 : "m" (cpu_local_area));   \
                                            \
    ptr_;                                   \
MACRO_END

#define cpu_local_var(var) (*cpu_local_ptr(var))

/* Generic interrupt-safe percpu accessors */

#define cpu_local_assign(var, val)          \
    asm("mov %0, %%fs:%1"                   \
                 : : "r" (val), "m" (var));

#define cpu_local_read(var)         \
MACRO_BEGIN                         \
    typeof(var) val_;               \
                                    \
    asm("mov %%fs:%1, %0"           \
                 : "=r" (val_)      \
                 : "m" (var));      \
                                    \
    val_;                           \
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

static inline bool
cpu_has_feature(const struct cpu *cpu, enum cpu_feature feature)
{
    return cpu_feature_map_test(&cpu->feature_map, feature);
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
    return cpu_has_feature(cpu_current(), CPU_FEATURE_PGE);
}

/*
 * Enable the use of global pages in the TLB.
 *
 * As a side effect, this function causes a complete TLB flush if global
 * pages were previously disabled.
 *
 * Implies a full memory barrier.
 * TODO Update barrier description.
 */
static __always_inline void
cpu_enable_global_pages(void)
{
    cpu_set_cr4(cpu_get_cr4() | CPU_CR4_PGE);
}

/*
 * CPUID instruction wrapper.
 *
 * The CPUID instruction is a serializing instruction.
 */
static __always_inline void
cpu_cpuid(unsigned int *eax, unsigned int *ebx, unsigned int *ecx,
          unsigned int *edx)
{
    asm volatile("cpuid" : "+a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)
                 : : "memory");
}

static inline void
cpu_get_msr(uint32_t msr, uint32_t *high, uint32_t *low)
{
    asm("rdmsr" : "=a" (*low), "=d" (*high) : "c" (msr));
}

static inline uint64_t
cpu_get_msr64(uint32_t msr)
{
    uint32_t high, low;

    cpu_get_msr(msr, &high, &low);
    return (((uint64_t)high << 32) | low);
}

/*
 * Implies a full memory barrier.
 */
static inline void
cpu_set_msr(uint32_t msr, uint32_t high, uint32_t low)
{
    asm volatile("wrmsr" : : "c" (msr), "a" (low), "d" (high) : "memory");
}

/*
 * Implies a full memory barrier.
 */
static inline void
cpu_set_msr64(uint32_t msr, uint64_t value)
{
    uint32_t low, high;

    low = value & 0xffffffff;
    high = value >> 32;
    cpu_set_msr(msr, high, low);
}

/*
 * Flush non-global TLB entries.
 *
 * Implies a full memory barrier.
 * TODO Update barrier description.
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
 * TODO Update barrier description.
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
 * TODO Update barrier description.
 */
static __always_inline void
cpu_tlb_flush_va(unsigned long va)
{
    asm volatile("invlpg (%0)" : : "r" (va) : "memory");
}

static inline unsigned int
cpu_cpuid_max_basic(const struct cpu *cpu)
{
    return cpu->cpuid_max_basic;
}

static inline unsigned int
cpu_vendor_id(const struct cpu *cpu)
{
    return cpu->vendor_id;
}

static inline unsigned int
cpu_family(const struct cpu *cpu)
{
    return cpu->family;
}

static inline unsigned int
cpu_phys_addr_width(const struct cpu *cpu)
{
    return cpu->phys_addr_width;
}

/*
 * Get CPU frequency in Hz.
 */
uint64_t cpu_get_freq(void);

/*
 * Busy-wait for a given amount of time, in microseconds.
 *
 * Implies a compiler barrier.
 */
void cpu_delay(unsigned long usecs);

/*
 * Log processor information.
 */
void cpu_log_info(const struct cpu *cpu);

/*
 * Register a local APIC.
 */
void cpu_mp_register_lapic(unsigned int apic_id, bool is_bsp);

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
void cpu_ap_setup(unsigned int ap_id);

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
    lapic_ipi_send(cpu_apic_id(cpu), CPU_EXC_XCALL);
}

/*
 * Send a scheduling interrupt to a remote processor.
 */
static inline void
cpu_send_thread_schedule(unsigned int cpu)
{
    lapic_ipi_send(cpu_apic_id(cpu), CPU_EXC_THREAD_SCHEDULE);
}

/*
 * Register an interrupt handler.
 *
 * This function is only available during system initialization, before the
 * scheduler is started. It is meant for architectural interrupts, including
 * interrupt controllers, and not directly for drivers, which should use
 * the machine-independent intr module instead.
 *
 * Registration is system-wide.
 */
void cpu_register_intr(unsigned int vector, cpu_intr_handler_fn_t fn);

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
 *  - access to percpu variables on all processors
 */
INIT_OP_DECLARE(cpu_mp_probe);

/*
 * This init operation provides :
 *  - cpu shutdown operations registered
 */
INIT_OP_DECLARE(cpu_setup_shutdown);

#endif /* __ASSEMBLER__ */

#endif /* X86_CPU_H */
