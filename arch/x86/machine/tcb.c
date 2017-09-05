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
 */

#include <stdnoreturn.h>

#include <kern/init.h>
#include <kern/thread.h>
#include <machine/cpu.h>
#include <machine/pmap.h>
#include <machine/strace.h>
#include <machine/tcb.h>

noreturn void tcb_context_load(struct tcb *tcb);
noreturn void tcb_start(void);
void tcb_context_restore(void);

struct tcb *tcb_current_ptr __percpu;

static void
tcb_stack_push(struct tcb *tcb, uintptr_t word)
{
    uintptr_t *ptr;

    ptr = (uintptr_t *)tcb->sp;
    ptr--;
    *ptr = word;
    tcb->sp = (uintptr_t)ptr;
}

#ifdef __LP64__

static void
tcb_stack_forge(struct tcb *tcb, void (*fn)(void *), void *arg)
{
    tcb_stack_push(tcb, (uintptr_t)arg);
    tcb_stack_push(tcb, (uintptr_t)fn);
    tcb_stack_push(tcb, (uintptr_t)tcb_start);  /* Return address */
    tcb_stack_push(tcb, CPU_EFL_ONE);           /* RFLAGS */
    tcb_stack_push(tcb, 0);                     /* RBX */
    tcb_stack_push(tcb, 0);                     /* R12 */
    tcb_stack_push(tcb, 0);                     /* R13 */
    tcb_stack_push(tcb, 0);                     /* R14 */
    tcb_stack_push(tcb, 0);                     /* R15 */
}

#else /* __LP64__ */

static void
tcb_stack_forge(struct tcb *tcb, void (*fn)(void *), void *arg)
{
    tcb_stack_push(tcb, (uintptr_t)arg);
    tcb_stack_push(tcb, (uintptr_t)fn);
    tcb_stack_push(tcb, (uintptr_t)tcb_start);  /* Return address */
    tcb_stack_push(tcb, CPU_EFL_ONE);           /* EFLAGS */
    tcb_stack_push(tcb, 0);                     /* EBX */
    tcb_stack_push(tcb, 0);                     /* EDI */
    tcb_stack_push(tcb, 0);                     /* ESI */
}

#endif /* __LP64__ */

int
tcb_build(struct tcb *tcb, void *stack, void (*fn)(void *), void *arg)
{
    int error;

    error = pmap_thread_build(thread_from_tcb(tcb));

    if (error) {
        return error;
    }

    tcb->bp = 0;
    tcb->sp = (uintptr_t)stack + TCB_STACK_SIZE;
    tcb_stack_forge(tcb, fn, arg);
    return 0;
}

void
tcb_cleanup(struct tcb *tcb)
{
    pmap_thread_cleanup(thread_from_tcb(tcb));
}

void __init
tcb_load(struct tcb *tcb)
{
    assert(!cpu_intr_enabled());

    tcb_set_current(tcb);
    tcb_context_load(tcb);
}

void
tcb_trace(const struct tcb *tcb)
{
    strace_show((uintptr_t)tcb_context_restore, tcb->bp);
}

static int __init
tcb_setup(void)
{
    return 0;
}

INIT_OP_DEFINE(tcb_setup,
               INIT_OP_DEP(cpu_setup, true));
