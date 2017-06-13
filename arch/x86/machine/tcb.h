/*
 * Copyright (c) 2012-2017 Richard Braun.
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

#include <assert.h>
#include <stdint.h>

#include <kern/macros.h>
#include <machine/cpu.h>

/*
 * Thread control block.
 */
struct tcb {
    uintptr_t bp;
    uintptr_t sp;
};

/*
 * Initialize a TCB.
 *
 * Prepare the given stack for execution. The context is defined so that it
 * will call thread_main(fn, arg) with interrupts disabled when loaded.
 *
 * In addition, initialize any thread-local machine-specific data.
 */
int tcb_init(struct tcb *tcb, void *stack, void (*fn)(void *), void *arg);

static inline struct tcb *
tcb_current(void)
{
    extern struct tcb *tcb_current_ptr;
    return cpu_local_read(tcb_current_ptr);
}

static inline void
tcb_set_current(struct tcb *tcb)
{
    extern struct tcb *tcb_current_ptr;
    cpu_local_assign(tcb_current_ptr, tcb);
}

/*
 * Load a TCB.
 *
 * Called with interrupts disabled. The caller context is lost.
 */
void __noreturn tcb_load(struct tcb *tcb);

/*
 * Context switch.
 *
 * Called with interrupts disabled.
 */
static inline void
tcb_switch(struct tcb *prev, struct tcb *next)
{
    void tcb_context_switch(struct tcb *prev, struct tcb *next);

    assert(!cpu_intr_enabled());

    tcb_set_current(next);
    tcb_context_switch(prev, next);
}

/*
 * Dump the stack trace of a TCB.
 *
 * The thread associated to the TCB must not be running.
 */
void tcb_trace(const struct tcb *tcb);

#endif /* _X86_TCB_H */
