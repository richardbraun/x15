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

#include <kern/init.h>
#include <kern/kernel.h>
#include <kern/thread.h>
#include <machine/cpu.h>
#include <test/test.h>
#include <vm/vm_page.h>

void __init
kernel_main(void)
{
    assert(!cpu_intr_enabled());

    init_setup();
    vm_page_log_info();

#ifdef X15_RUN_TEST_MODULE
    test_setup();
#endif /* X15_RUN_TEST_MODULE */

    /*
     * Enabling application processors is done late in the boot process for
     * two reasons :
     *  - It's much simpler to bootstrap with interrupts disabled on all
     *    processors, enabling them only when necessary on the BSP.
     *  - Depending on the architecture, the pmap module could create per
     *    processor page tables. Once done, keeping the kernel page tables
     *    synchronized requires interrupts (and potentially scheduling)
     *    enabled on all processors.
     *
     * It is highly recommended not to do anything else than starting the
     * scheduler right after this call.
     */
    cpu_mp_setup();

    thread_run_scheduler();

    /* Never reached */
}

void __init
kernel_ap_main(void)
{
    assert(!cpu_intr_enabled());

    thread_run_scheduler();

    /* Never reached */
}
