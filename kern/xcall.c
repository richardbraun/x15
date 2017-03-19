/*
 * Copyright (c) 2014 Richard Braun.
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

#include <stddef.h>

#include <kern/assert.h>
#include <kern/macros.h>
#include <kern/param.h>
#include <kern/percpu.h>
#include <kern/spinlock.h>
#include <kern/thread.h>
#include <kern/xcall.h>
#include <machine/mb.h>
#include <machine/cpu.h>

struct xcall {
    xcall_fn_t fn;
    void *arg;
} __aligned(CPU_L1_SIZE);

/*
 * Per-CPU data.
 *
 * Send calls are sent to remote processors. Their access is synchronized
 * by disabling preemption.
 *
 * The received call points to either NULL if there is no call to process,
 * or a remote send call otherwise. The lock serializes the complete
 * inter-processor operation, i.e. setting the received call pointer,
 * communication through an IPI, and waiting for the processor to
 * acknowledge execution. By serializing interrupts, it is certain that
 * there is a 1:1 mapping between interrupts and cross-calls, allowing
 * the handler to process only one cross-call instead of iterating over
 * a queue. This way, interrupts with higher priority can be handled
 * between multiple cross-calls.
 */
struct xcall_cpu_data {
    struct xcall send_calls[X15_MAX_CPUS];

    struct xcall *recv_call;
    struct spinlock lock;
} __aligned(CPU_L1_SIZE);

static struct xcall_cpu_data xcall_cpu_data __percpu;

static inline void
xcall_set(struct xcall *call, xcall_fn_t fn, void *arg)
{
    call->fn = fn;
    call->arg = arg;
}

static void
xcall_cpu_data_init(struct xcall_cpu_data *cpu_data)
{
    cpu_data->recv_call = NULL;
    spinlock_init(&cpu_data->lock);
}

static struct xcall_cpu_data *
xcall_cpu_data_get(void)
{
    assert(!thread_preempt_enabled());
    return cpu_local_ptr(xcall_cpu_data);
}

static struct xcall *
xcall_cpu_data_get_send_call(struct xcall_cpu_data *cpu_data, unsigned int cpu)
{
    assert(cpu < ARRAY_SIZE(cpu_data->send_calls));
    return &cpu_data->send_calls[cpu];
}

static struct xcall *
xcall_cpu_data_get_recv_call(struct xcall_cpu_data *cpu_data)
{
    return cpu_data->recv_call;
}

static void
xcall_cpu_data_clear_recv_call(struct xcall_cpu_data *cpu_data)
{
    cpu_data->recv_call = NULL;
}

void
xcall_setup(void)
{
    unsigned int i;

    for (i = 0; i < cpu_count(); i++) {
        xcall_cpu_data_init(percpu_ptr(xcall_cpu_data, i));
    }
}

void
xcall_call(xcall_fn_t fn, void *arg, unsigned int cpu)
{
    struct xcall_cpu_data *local_data, *remote_data;
    struct xcall *call;

    assert(fn != NULL);

    remote_data = percpu_ptr(xcall_cpu_data, cpu);

    thread_preempt_disable();

    if (cpu == cpu_id()) {
        unsigned long flags;

        cpu_intr_save(&flags);
        fn(arg);
        cpu_intr_restore(flags);
        goto out;
    }

    local_data = xcall_cpu_data_get();
    call = xcall_cpu_data_get_send_call(local_data, cpu);
    xcall_set(call, fn, arg);

    spinlock_lock(&remote_data->lock);

    remote_data->recv_call = call;

    /* This barrier pairs with the one implied by the received IPI */
    mb_store();

    cpu_send_xcall(cpu);

    while (remote_data->recv_call != NULL) {
        cpu_pause();
    }

    spinlock_unlock(&remote_data->lock);

    /* This barrier pairs with the one in the interrupt handler */
    mb_load();

out:
    thread_preempt_enable();
}

void
xcall_intr(void)
{
    struct xcall_cpu_data *cpu_data;
    struct xcall *call;

    thread_assert_interrupted();

    cpu_data = xcall_cpu_data_get();
    call = xcall_cpu_data_get_recv_call(cpu_data);
    call->fn(call->arg);
    mb_store();
    xcall_cpu_data_clear_recv_call(cpu_data);
}
