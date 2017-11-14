/*
 * Copyright (c) 2017 Richard Braun.
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

#ifndef _ARM_CPU_H
#define _ARM_CPU_H

#include <limits.h>

#include <machine/cpu_armv6.h>
#include <machine/cpu_armv7.h>

/*
 * L1 cache line size.
 *
 * XXX Use this value until processor selection is available.
 */
#define CPU_L1_SIZE 32

/*
 * Data alignment, normally the word size.
 *
 * TODO Check.
 */
#define CPU_DATA_SHIFT 2
#define CPU_DATA_ALIGN (1 << CPU_DATA_SHIFT)

/*
 * Function alignment.
 *
 * Aligning functions improves instruction fetching.
 *
 * Used for assembly functions only.
 *
 * XXX Use this value until processor selection is available.
 */
#define CPU_TEXT_SHIFT 4
#define CPU_TEXT_ALIGN (1 << CPU_TEXT_SHIFT)

/*
 * PSR flags.
 */
#define CPU_PSR_I       0x00000080

#ifndef __ASSEMBLER__

#include <stdbool.h>
#include <stdnoreturn.h>

#include <kern/init.h>

struct cpu {
    unsigned int id;
};

/*
 * Return the content of the CPSR register.
 *
 * Implies a compiler barrier.
 */
static __always_inline unsigned long
cpu_get_cpsr(void)
{
    unsigned long cpsr;

    asm volatile("mrs %0, cpsr"
                 : "=r" (cpsr)
                 : : "memory");

    return cpsr;
}

/*
 * Restore the content of the CPSR register, possibly enabling interrupts.
 *
 * Implies a compiler barrier.
 */
static __always_inline void
cpu_intr_restore(unsigned long flags)
{
    asm volatile("msr cpsr_c, %0"
                 : : "r" (flags)
                 : "memory");
}

/*
 * Disable local interrupts, returning the previous content of the CPSR
 * register.
 *
 * Implies a compiler barrier.
 */
static __always_inline void
cpu_intr_save(unsigned long *flags)
{
    *flags = cpu_get_cpsr();
    cpu_intr_disable();
}

static __always_inline bool
cpu_intr_enabled(void)
{
    unsigned long cpsr;

    cpsr = cpu_get_cpsr();
    return !(cpsr & CPU_PSR_I);
}

void cpu_halt_broadcast(void);

static inline struct cpu *
cpu_current(void)
{
    return NULL;
}

static inline unsigned int
cpu_id(void)
{
    return 0;
}

static inline unsigned int
cpu_count(void)
{
    return 1;
}

/*
 * Log processor information.
 */
void cpu_log_info(const struct cpu *cpu);

void cpu_mp_setup(void);

static inline void
cpu_send_xcall(unsigned int cpu)
{
    (void)cpu;
}

static inline void
cpu_send_thread_schedule(unsigned int cpu)
{
    (void)cpu;
}

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

#endif /* __ASSEMBLER__ */

#endif /* _ARM_CPU_H */
