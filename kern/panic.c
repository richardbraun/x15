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
#include <stdio.h>

#include <kern/atomic.h>
#include <kern/init.h>
#include <kern/panic.h>
#include <machine/cpu.h>
#include <machine/strace.h>

static unsigned int panic_done;

void
panic(const char *format, ...)
{
    va_list list;
    unsigned long already_done;

    already_done = atomic_swap(&panic_done, 1, ATOMIC_SEQ_CST);

    if (already_done) {
        for (;;) {
            cpu_idle();
        }
    }

    cpu_intr_disable();
    cpu_halt_broadcast();

    printf("\npanic: ");
    va_start(list, format);
    vprintf(format, list);
    printf("\n");
    strace_dump();

    cpu_halt();

    /*
     * Never reached.
     */
}

static int __init
panic_setup(void)
{
    return 0;
}

INIT_OP_DEFINE(panic_setup,
               INIT_OP_DEP(cpu_setup, true),
               INIT_OP_DEP(printf_setup, true),
               INIT_OP_DEP(strace_setup, true));
