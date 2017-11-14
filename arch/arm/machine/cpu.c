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

#include <kern/init.h>
#include <kern/percpu.h>
#include <machine/cpu.h>

/*
 * Processor descriptor, one per CPU.
 */
struct cpu cpu_desc __percpu;

void cpu_halt_broadcast(void)
{
}

void cpu_log_info(const struct cpu *cpu)
{
    (void)cpu;
}

void cpu_mp_setup(void)
{
}

static void __init
cpu_init(struct cpu *cpu, unsigned int id)
{
    cpu->id = id;
}

static void __init
cpu_set_percpu_area(void *area)
{
#ifdef CONFIG_SMP
    cpu_set_tpidrprw((uintptr_t)area);
#else /* CONFIG_SMP */
    /* TODO Single-processor support */
    cpu_halt();
#endif /* CONFIG_SMP */
}

/*
 * Initialize the given cpu structure for the current processor.
 */
static void __init
cpu_init_local(struct cpu *cpu)
{
    cpu_set_percpu_area(percpu_area(cpu->id));
}

static int __init
cpu_setup(void)
{
    struct cpu *cpu;

    cpu = percpu_ptr(cpu_desc, 0);
    cpu_init(cpu, 0);
    cpu_init_local(cpu);

    /* TODO Provide cpu_delay() */

    return 0;
}

INIT_OP_DEFINE(cpu_setup,
               INIT_OP_DEP(percpu_bootstrap, true));

static int __init
cpu_mp_probe(void)
{
    return 0;
}

INIT_OP_DEFINE(cpu_mp_probe);
