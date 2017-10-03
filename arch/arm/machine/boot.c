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

#include <kern/init.h>
#include <machine/boot.h>
#include <machine/cpu.h>
#include <machine/pmap.h>
#include <vm/vm_kmem.h>

alignas(CPU_DATA_ALIGN) char boot_stack[BOOT_STACK_SIZE] __bootdata;

static char boot_hello_msg[] __bootdata = "Hello, world!\r\n";

static void __boot
boot_hello_world(void)
{
    volatile unsigned long *uart_data_reg = (volatile unsigned long *)0x9000000;
    const char *s = boot_hello_msg;

    while (*s != '\0') {
        *uart_data_reg = *s;
        s++;
    }
}

void boot_setup_paging(void);

void __boot
boot_setup_paging(void)
{
    boot_hello_world();

    for (;;);
}

void __init
boot_log_info(void)
{
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
