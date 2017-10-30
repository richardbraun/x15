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

#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <kern/init.h>
#include <kern/bootmem.h>
#include <machine/boot.h>
#include <machine/cpu.h>
#include <machine/pmap.h>
#include <machine/pmem.h>
#include <vm/vm_kmem.h>

#define BOOT_UART_DATA_REG 0x9000000

alignas(CPU_DATA_ALIGN) char boot_stack[BOOT_STACK_SIZE] __bootdata;

pmap_pte_t * boot_setup_paging(void);

void boot_main(void);

void __boot
boot_panic(const char *s)
{
    volatile unsigned long *uart_data_reg;

    uart_data_reg = (volatile unsigned long *)BOOT_UART_DATA_REG;

    while (*s != '\0') {
        *uart_data_reg = *s;
        s++;
    }

    for (;;);
}

pmap_pte_t * __boot
boot_setup_paging(void)
{
    bootmem_register_zone(PMEM_ZONE_DMA, true, PMEM_RAM_START, PMEM_DMA_LIMIT);
    bootmem_setup();
    return pmap_setup_paging();
}

void __init
boot_log_info(void)
{
}

static void __init
boot_clear_bss(void)
{
    memset(&_bss, 0, &_end - &_bss);
}

void __init
boot_main(void)
{
    boot_clear_bss();
    kernel_main();

    /* Never reached */
}

/*
 * Init operation aliases.
 */

static int __init
boot_bootstrap_console(void)
{
    return 0;
}

INIT_OP_DEFINE(boot_bootstrap_console);

static int __init
boot_setup_console(void)
{
    return 0;
}

INIT_OP_DEFINE(boot_setup_console);

static int __init
boot_load_vm_page_zones(void)
{
    return 0;
}

INIT_OP_DEFINE(boot_load_vm_page_zones);

static int __init
boot_setup_intr(void)
{
    return 0;
}

INIT_OP_DEFINE(boot_setup_intr);

static int __init
boot_setup_shutdown(void)
{
    return 0;
}

INIT_OP_DEFINE(boot_setup_shutdown);
