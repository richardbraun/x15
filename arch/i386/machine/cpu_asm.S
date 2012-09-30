/*
 * Copyright (c) 2011, 2012 Richard Braun.
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

#define __ASSEMBLY__

#include <machine/asm.h>
#include <machine/cpu.h>

.text

ENTRY(cpu_load_gdt)
 movl 4(%esp), %eax
 lgdt (%eax)

 movl $(CPU_GDT_SELECTOR(CPU_GDT_DATA_IDX)), %eax
 movl %eax, %ds
 movl %eax, %es
 movl %eax, %ss

 xorl %eax, %eax
 movl %eax, %gs

 movl $(CPU_GDT_SELECTOR(CPU_GDT_CPU_IDX)), %eax
 movl %eax, %fs

 /* Alter the stack to reload the code segment using a far return */
 popl %eax
 pushl $(CPU_GDT_SELECTOR(CPU_GDT_CODE_IDX))
 pushl %eax
 lret
END(cpu_load_gdt)

/*
 * TODO: traps handling.
 */
ENTRY(cpu_trap_default)
 iret
END(cpu_trap_default)

ENTRY(cpu_trap_lapic_timer_intr)
 call lapic_timer_intr
 iret
END(cpu_trap_lapic_timer_intr)

ENTRY(cpu_trap_lapic_spurious_intr)
 iret
END(cpu_trap_lapic_spurious_intr)
