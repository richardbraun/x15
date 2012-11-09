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
 */

#include <kern/error.h>
#include <kern/init.h>
#include <kern/kmem.h>
#include <kern/param.h>
#include <kern/stddef.h>
#include <kern/string.h>
#include <kern/thread.h>
#include <machine/cpu.h>
#include <machine/tcb.h>
#include <machine/trap.h>

static struct kmem_cache tcb_cache;

void __init
tcb_setup(void)
{
    kmem_cache_init(&tcb_cache, "tcb", sizeof(struct tcb),
                    0, NULL, NULL, NULL, 0);
}

#ifdef __LP64__

static void
tcb_init_stack(struct tcb *tcb, void *stack, const struct thread *thread)
{
    struct trap_frame *frame;

    frame = (struct trap_frame *)(stack + STACK_SIZE) - 1;
    memset(frame, 0, sizeof(*frame));
    frame->rdi = (unsigned long)thread;
    frame->rip = (unsigned long)thread_main;
    frame->cs = CPU_GDT_SEL_CODE;
    frame->rflags = CPU_EFL_IF | CPU_EFL_ONE;
    frame->rsp = (unsigned long)(stack + STACK_SIZE);
    frame->ss = CPU_GDT_SEL_DATA;
    tcb->frame = frame;
}

#else /* __LP64__ */

static void
tcb_init_stack(struct tcb *tcb, void *stack, const struct thread *thread)
{
    struct trap_frame *frame;
    const struct thread **arg;
    const void **ret_addr;
    void *ptr;
    size_t size;

    /* Fake a function call (return address and argument) */
    ptr = stack + STACK_SIZE - (2 * sizeof(long));
    ret_addr = ptr;
    *ret_addr = 0;
    arg = ptr + sizeof(long);
    *arg = thread;

    /* Exclude user space stack registers */
    size = sizeof(*frame) - (2 * sizeof(long));
    frame = ptr - size;
    memset(frame, 0, size);
    frame->ds = CPU_GDT_SEL_DATA;
    frame->es = CPU_GDT_SEL_DATA;
    frame->fs = CPU_GDT_SEL_CPU;
    frame->gs = CPU_GDT_SEL_NULL;
    frame->eip = (unsigned long)thread_main;
    frame->cs = CPU_GDT_SEL_CODE;
    frame->eflags = CPU_EFL_IF | CPU_EFL_ONE;
    tcb->frame = frame;
}

#endif /* __LP64__ */

int
tcb_create(struct tcb **tcbp, void *stack, const struct thread *thread)
{
    struct tcb *tcb;

    tcb = kmem_cache_alloc(&tcb_cache);

    if (tcb == NULL)
        return ERROR_NOMEM;

    tcb_init_stack(tcb, stack, thread);
    *tcbp = tcb;
    return 0;
}

void
tcb_load(struct tcb *tcb)
{
    trap_load(tcb->frame);
}
