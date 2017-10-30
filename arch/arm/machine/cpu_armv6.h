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

#ifndef _ARM_CPU_ARMV6_H
#define _ARM_CPU_ARMV6_H

#if CONFIG_ARM_ARCH >= 6

#ifndef __ASSEMBLER__

#include <stdbool.h>
#include <stdnoreturn.h>

#include <kern/macros.h>

/*
 * Enable local interrupts.
 *
 * Implies a compiler barrier.
 */
static __always_inline void
cpu_intr_enable(void)
{
    asm volatile("cpsie i" : : : "memory", "cc");
}

/*
 * Disable local interrupts.
 *
 * Implies a compiler barrier.
 */
static __always_inline void
cpu_intr_disable(void)
{
    asm volatile("cpsid i" : : : "memory", "cc");
}

static __always_inline void
cpu_pause(void)
{
    for (;;);
}

/*
 * Make the CPU idle until the next interrupt.
 *
 * Implies a compiler barrier.
 */
static __always_inline void
cpu_idle(void)
{
    asm volatile("wfi" : : : "memory");
}

noreturn static __always_inline void
cpu_halt(void)
{
    cpu_intr_disable();

    for (;;) {
        cpu_idle();
    }
}

#endif /* __ASSEMBLER__ */

#endif /* ARM_ARCH >= 6 */

#endif /* _ARM_CPU_ARMV6_H */
