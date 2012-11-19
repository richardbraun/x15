/*
 * Copyright (c) 2012 Richard Braun.
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
 * Thread control block.
 */

#ifndef _X86_TCB_H
#define _X86_TCB_H

#include <kern/macros.h>
#include <machine/trap.h>

/*
 * Architecture specific thread data.
 */
struct tcb {
    unsigned long sp;
    unsigned long ip;
};

/*
 * Initialize a TCB.
 *
 * Prepare the given stack for execution. The context is defined so that it
 * will call fn() with interrupts disabled when loaded.
 */
void tcb_init(struct tcb *tcb, void *stack, void (*fn)(void));

/*
 * Load a TCB.
 *
 * The caller context is lost.
 */
void __noreturn tcb_load(struct tcb *tcb);

/*
 * Context switch.
 *
 * Called with interrupts disabled.
 */
void tcb_switch(struct tcb *prev, struct tcb *next);

#endif /* _X86_TCB_H */
