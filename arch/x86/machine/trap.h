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

#ifndef _X86_TRAP_H
#define _X86_TRAP_H

/*
 * Trap vectors.
 */
#define T_DIVIDE_ERROR          0
#define T_DEBUG                 1
#define T_NMI                   2
#define T_INT3                  3
#define T_OVERFLOW              4
#define T_OUT_OF_BOUNDS         5
#define T_INVALID_OPCODE        6
#define T_NO_FPU                7
#define T_DOUBLE_FAULT          8
#define T_FPU_FAULT             9
#define T_INVALID_TSS           10
#define T_SEGMENT_NOT_PRESENT   11
#define T_STACK_FAULT           12
#define T_GENERAL_PROTECTION    13
#define T_PAGE_FAULT            14
#define T_FLOATING_POINT_ERROR  16
#define T_WATCHPOINT            17
#define T_MACHINE_CHECK         18
#define T_SSE_FAULT             19
#define T_APIC_TIMER_INTR       253
#define T_APIC_ERROR_INTR       254
#define T_APIC_SPURIOUS_INTR    255

#endif /* _X86_TRAP_H */
