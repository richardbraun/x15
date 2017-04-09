/*
 * Copyright (c) 2014-2017 Richard Braun.
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
 *
 *
 * Per-CPU variables.
 *
 * This module supports statically allocated per-CPU variables only. Each
 * active processor gets its own block of pages, called percpu area, where
 * percpu variables are stored. The offset of a percpu variable is fixed
 * and added to the base of the percpu area to obtain the real address of
 * the variable.
 *
 * A statically allocated percpu variable should be defined with the
 * __percpu macro, e.g. :
 *
 * struct s var __percpu;
 *
 * Obviously, the variable cannot be directly accessed. Instead, percpu
 * variables can be accessed with the following accessors :
 *  - percpu_ptr()
 *  - percpu_var()
 *
 * The cpu module is expected to provide the following accessors to access
 * percpu variables from the local processor :
 *  - cpu_local_ptr()
 *  - cpu_local_var()
 *
 * These accessors may generate optimized code.
 *
 * Architecture-specific code must enforce that the percpu section starts
 * at 0, thereby making the addresses of percpu variables offsets into the
 * percpu area. It must also make sure the _percpu and _percpu_end symbols
 * have valid virtual addresses, included between _init (but not part of
 * the init section) and _end.
 *
 * Unless otherwise specified, accessing a percpu variable is not
 * interrupt-safe.
 */

#ifndef _KERN_PERCPU_H
#define _KERN_PERCPU_H

#include <stdint.h>

#include <kern/assert.h>
#include <kern/macros.h>

#define PERCPU_SECTION .percpu
#define __percpu __section(QUOTE(PERCPU_SECTION))

/*
 * Boundaries of the percpu section.
 *
 * The addresses of these symbols must be valid, even if the percpu section
 * itself has different addresses.
 */
extern char _percpu;
extern char _percpu_end;

/*
 * Expands to the address of a percpu variable.
 */
#define percpu_ptr(var, cpu) \
    ((typeof(var) *)(percpu_area(cpu) + ((uintptr_t)(&(var)))))

/*
 * Expands to the lvalue of a percpu variable.
 */
#define percpu_var(var, cpu) (*(percpu_ptr(var, cpu)))

static inline void *
percpu_area(unsigned int cpu)
{
    extern void *percpu_areas[X15_MAX_CPUS];
    void *area;

    assert(cpu < X15_MAX_CPUS);
    area = percpu_areas[cpu];
    assert(area != NULL);
    return area;
}

/*
 * Early initialization of the percpu module.
 *
 * This function registers the percpu section as the percpu area of the
 * BSP. If a percpu variable is modified before calling percpu_setup(),
 * the modification will be part of the percpu section and propagated to
 * new percpu areas.
 */
void percpu_bootstrap(void);

/*
 * Complete initialization of the percpu module.
 *
 * The BSP keeps using the percpu section, but its content is copied to a
 * dedicated block of memory used as a template for subsequently added
 * processors.
 */
void percpu_setup(void);

/*
 * Register a processor.
 *
 * This function creates a percpu area from kernel virtual memory for the
 * given processor. The created area is filled from the content of the
 * percpu section.
 */
int percpu_add(unsigned int cpu);

/*
 * Release init data allocated for setup.
 */
void percpu_cleanup(void);

#endif /* _KERN_PERCPU_H */
