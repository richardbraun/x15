/*
 * Copyright (c) 2011-2017 Richard Braun.
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

#ifndef _X86_LAPIC_H
#define _X86_LAPIC_H

#include <stdbool.h>
#include <stdint.h>

#include <machine/trap.h>

/*
 * Send an end-of-interrupt message to the local APIC.
 */
void lapic_eoi(void);

/*
 * Report whether the local APIC is actually used or not.
 */
bool lapic_unused(void);

/*
 * Initialize the lapic module for the sole purpose of reporting that
 * it's actually not used.
 */
void lapic_setup_unused(void);

/*
 * Set up the lapic module.
 */
void lapic_setup(uint32_t map_addr);

/*
 * Set up the local APIC for an AP.
 */
void lapic_ap_setup(void);

/*
 * Functions used when initializing an AP.
 */
void lapic_ipi_init_assert(uint32_t apic_id);
void lapic_ipi_init_deassert(uint32_t apic_id);
void lapic_ipi_startup(uint32_t apic_id, uint32_t vector);

/*
 * Fixed/broadcast inter-processor interrupts.
 */
void lapic_ipi_send(uint32_t apic_id, uint32_t vector);
void lapic_ipi_broadcast(uint32_t vector);

/*
 * Interrupt handlers.
 */
void lapic_timer_intr(struct trap_frame *frame);
void lapic_error_intr(struct trap_frame *frame);
void lapic_spurious_intr(struct trap_frame *frame);

#endif /* _X86_LAPIC_H */
