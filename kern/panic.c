/*
 * Copyright (c) 2010-2014 Richard Braun.
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

#include <stdarg.h>

#include <kern/atomic.h>
#include <kern/panic.h>
#include <kern/printk.h>
#include <machine/cpu.h>
#include <machine/strace.h>

static unsigned int panic_done;

void
panic(const char *format, ...)
{
    va_list list;
    unsigned long already_done;

    already_done = atomic_swap_seq_cst(&panic_done, 1);

    if (already_done) {
        for (;;) {
            cpu_idle();
        }
    }

    cpu_intr_disable();
    cpu_halt_broadcast();

    printk("\npanic: ");
    va_start(list, format);
    vprintk(format, list);
    printk("\n");
    strace_dump();

    cpu_halt();

    /*
     * Never reached.
     */
}
