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

#ifndef _ARM_CPU_ARMV7_H
#define _ARM_CPU_ARMV7_H

#if CONFIG_ARM_ARCH >= 7

#ifndef __ASSEMBLER__

#include <stdint.h>

#include <kern/macros.h>

/*
 * Get the value of the TPIDRPRW register.
 */
static inline uintptr_t
cpu_get_tpidrprw(void)
{
    uintptr_t value;

    asm("mrc p15, 0, %0, c13, c0, 4" : "=r" (value));
    return value;
}

/*
 * Set the value of the TPIDRPRW register.
 *
 * Implies a compiler barrier.
 */
static inline void
cpu_set_tpidrprw(uintptr_t value)
{
    asm volatile("mcr p15, 0, %0, c13, c0, 4" : : "r" (value) : "memory");
}

/* TODO Rework into common code */
#define cpu_local_ptr(var)                                          \
MACRO_BEGIN                                                         \
    uintptr_t ___percpu_area;                                       \
    uintptr_t ___offset;                                            \
    typeof(var) *___ptr;                                            \
                                                                    \
    ___percpu_area = cpu_get_tpidrprw();                            \
    ___offset = (uintptr_t)(&(var));                                \
    ___ptr = (typeof(var) *)(___percpu_area + ___offset);           \
    ___ptr;                                                         \
MACRO_END

/* TODO Rework into common code */
#define cpu_local_var(var) (*cpu_local_ptr(var))

/* Interrupt-safe percpu accessors for basic types */

/* TODO Rework into common code */
#define cpu_local_assign(var, val)                                  \
MACRO_BEGIN                                                         \
    unsigned long ___flags;                                         \
                                                                    \
    cpu_intr_save(&___flags);                                       \
    cpu_local_var(var) = val;                                       \
    cpu_intr_restore(___flags);                                     \
MACRO_END

/* TODO Rework into common code */
#define cpu_local_read(var)                                         \
MACRO_BEGIN                                                         \
    unsigned long ___flags;                                         \
    typeof(var) ___val;                                             \
                                                                    \
    cpu_intr_save(&___flags);                                       \
    ___val = cpu_local_var(var);                                    \
    cpu_intr_restore(___flags);                                     \
                                                                    \
    ___val;                                                         \
MACRO_END

#endif /* __ASSEMBLER__ */

#endif /* ARM_ARCH >= 7 */

#endif /* _ARM_CPU_ARMV7_H */
