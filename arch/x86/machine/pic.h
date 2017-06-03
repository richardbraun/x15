/*
 * Copyright (c) 2012-2017 Richard Braun.
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

#ifndef _X86_PIC_H
#define _X86_PIC_H

/*
 * Interrupts per PIC.
 */
#define PIC_NR_INTRS    8

/*
 * Maximum global interrupt number.
 */
#define PIC_MAX_INTR    ((PIC_NR_INTRS * 2) - 1)

/*
 * Initialize the pic module.
 */
void pic_setup(void);

/*
 * Initialize the pic module in an APIC system.
 *
 * This function is called by the acpi module if ACPI reports the presence
 * of legacy interrupt controllers.
 *
 * Since it doesn't register the legacy PIC as an interrupt controller, the
 * acpi module must have registered I/O APICs before calling this function.
 */
void pic_setup_disabled(void);

#endif /* _X86_PIC_H */
