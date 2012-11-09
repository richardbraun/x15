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
 * Forward declaration.
 */
struct thread;

/*
 * Architecture specific thread data.
 */
struct tcb {
    struct trap_frame *frame;
};

/*
 * Set up the tcb module.
 */
void tcb_setup(void);

/*
 * Create a TCB.
 *
 * Prepare the given stack for execution.
 */
int tcb_create(struct tcb **tcbp, void *stack, const struct thread *thread);

/*
 * Load a TCB.
 *
 * The caller context is lost.
 */
void __noreturn tcb_load(struct tcb *tcb);

#endif /* _X86_TCB_H */
