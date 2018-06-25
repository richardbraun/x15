/*
 * Copyright (c) 2018 Remy Noel.
 * Copyright (c) 2018 Richard Braun.
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
 * PMU driver for AMD processors.
 */

#ifndef X86_PMU_AMD_H
#define X86_PMU_AMD_H

#include <kern/init.h>

/*
 * This init operation provides :
 *  - module fully initialized
 */
INIT_OP_DECLARE(pmu_amd_setup);

#endif /* X86_PMU_AMD_H */
