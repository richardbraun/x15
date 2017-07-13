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
 *
 *
 * Multiprocessor information gathering module, supporting the ACPI
 * specification v1.0.
 */

#ifndef _X86_ACPI_H
#define _X86_ACPI_H

#include <kern/init.h>

/*
 * This init operation provides :
 *  - Multiprocessor probing
 *  - registration of I/O APIC interrupt controllers
 *  - registration of ACPI shutdown operations
 */
INIT_OP_DECLARE(acpi_setup);

#endif /* _X86_ACPI_H */
