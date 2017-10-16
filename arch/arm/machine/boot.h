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
#include <machine/page.h>
#include <machine/pmap.h>
#include <machine/pmem.h>

/*
 * Size of the stack used when booting a processor.
 */
#define BOOT_STACK_SIZE PAGE_SIZE

#define BOOT_LOAD_SECTION .boot.load
#define BOOT_TEXT_SECTION .boot.text
#define BOOT_DATA_SECTION .boot.data

#define BOOT_KERNEL_OFFSET  (PMAP_START_KERNEL_ADDRESS - PMEM_RAM_START)

#define BOOT_RTOL(addr) ((addr) - PMEM_RAM_START)
#define BOOT_VTOL(addr) ((addr) - PMAP_START_KERNEL_ADDRESS)

#define BOOT_VTOP(addr) ((addr) - BOOT_KERNEL_OFFSET)

#define BOOT_MEM_BLOCK_BITS     10
#define BOOT_MEM_NR_FREE_LISTS  5

#ifndef __ASSEMBLER__

#include <stdnoreturn.h>

#include <kern/init.h>

#define __boot     __section(QUOTE(BOOT_TEXT_SECTION))
#define __bootdata __section(QUOTE(BOOT_DATA_SECTION)) __attribute__((used))

/*
 * Boundaries of the .boot section.
 */
extern char _boot;
extern char _boot_end;

noreturn void boot_panic(const char *s);

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
