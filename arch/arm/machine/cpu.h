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

/*
 * L1 cache line size.
 *
 * XXX Use this value until processor selection is available.
 */
#define CPU_L1_SIZE 32

/*
 * Data alignment, normally the word size.
 */
#define CPU_DATA_ALIGN (LONG_BIT / 8)

#ifndef __ASSEMBLER__

#include <stdbool.h>
#include <stdnoreturn.h>

#include <kern/init.h>

struct cpu {
};

static __always_inline void
cpu_intr_enable(void)
{
}

static __always_inline void
cpu_intr_disable(void)
{
}

static __always_inline void
cpu_intr_restore(unsigned long flags)
{
    (void)flags;
}

static __always_inline void
cpu_intr_save(unsigned long *flags)
{
    (void)flags;
}

static __always_inline bool
cpu_intr_enabled(void)
{
    return false;
}

static __always_inline void
cpu_pause(void)
{
}

static __always_inline void
cpu_idle(void)
{
}

noreturn static __always_inline void
cpu_halt(void)
{
    for (;;);
}

void cpu_halt_broadcast(void);

#define cpu_local_ptr(var) (&(var))

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
