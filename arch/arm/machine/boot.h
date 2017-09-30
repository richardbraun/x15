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

#ifndef _ARM_BOOT_H
#define _ARM_BOOT_H

#include <kern/macros.h>
#include <machine/pmap.h>

#define BOOT_OFFSET DECL_CONST(0x0, UL)

#define BOOT_VTOP(addr) ((addr) - PMAP_KERNEL_OFFSET)

#ifndef __ASSEMBLER__

#include <kern/init.h>

/*
 * Log kernel version and other architecture-specific information.
 */
void boot_log_info(void);

/*
 * This init operation provides :
 *  - all console devices are bootstrapped
 */
INIT_OP_DECLARE(boot_bootstrap_console);

/*
 * This init operation provides :
 *  - all console devices are fully initialized
 */
INIT_OP_DECLARE(boot_setup_console);

/*
 * This init operation provides :
 *  - physical memory has been loaded to the VM system
 */
INIT_OP_DECLARE(boot_load_vm_page_zones);

/*
 * This init operation provides :
 *  - all interrupt controllers have been registered
 */
INIT_OP_DECLARE(boot_setup_intr);

/*
 * This init operation provides :
 *  - all shutdown operations have been registered
 */
INIT_OP_DECLARE(boot_setup_shutdown);

#endif /* __ASSEMBLER__ */

#endif /* _ARM_BOOT_H */
