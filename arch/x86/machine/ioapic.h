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

#ifndef _KERN_IOAPIC_H
#define _KERN_IOAPIC_H

#include <stdint.h>

/*
 * Initialize the ioapic module.
 */
void ioapic_setup(void);

/*
 * Register an I/O APIC controller.
 */
void ioapic_register(unsigned int id, uintptr_t addr, unsigned int gsi_base);

/*
 * Enable/disable an interrupt line.
 *
 * The given interrupt is routed to the given (cpu, vector) destination.
 */
int ioapic_enable(unsigned int intr, unsigned int cpu, unsigned int vector);
void ioapic_disable(unsigned int intr);

#endif /* _KERN_IOAPIC_H */
