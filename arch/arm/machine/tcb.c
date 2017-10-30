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

#include <kern/error.h>
#include <kern/init.h>
#include <machine/cpu.h>
#include <machine/tcb.h>

int
tcb_build(struct tcb *tcb, void *stack, void (*fn)(void *), void *arg)
{
    (void)tcb;
    (void)stack;
    (void)fn;
    (void)arg;
    return ERROR_AGAIN;
}

void
tcb_cleanup(struct tcb *tcb)
{
    (void)tcb;
}

static int __init
tcb_setup(void)
{
    cpu_halt();
    return 0;
}

INIT_OP_DEFINE(tcb_setup);
