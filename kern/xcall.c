/*
 * Copyright (c) 2014-2017 Richard Braun.
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

#include <assert.h>
#include <stdalign.h>
#include <stddef.h>

#include <kern/atomic.h>
#include <kern/init.h>
#include <kern/macros.h>
#include <kern/percpu.h>
#include <kern/spinlock.h>
#include <kern/thread.h>
#include <kern/xcall.h>
#include <machine/cpu.h>

struct xcall {
    alignas(CPU_L1_SIZE) xcall_fn_t fn;
    void *arg;
};

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
    alignas(CPU_L1_SIZE) struct xcall send_calls[X15_MAX_CPUS];

    struct xcall *recv_call;
    struct spinlock lock;
};

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
xcall_cpu_data_get_recv_call(const struct xcall_cpu_data *cpu_data)
{
    return atomic_load(&cpu_data->recv_call, ATOMIC_ACQUIRE);
}

static void
xcall_cpu_data_set_recv_call(struct xcall_cpu_data *cpu_data,
                             struct xcall *call)
{
    atomic_store(&cpu_data->recv_call, call, ATOMIC_RELEASE);
}

static void
xcall_cpu_data_clear_recv_call(struct xcall_cpu_data *cpu_data)
{
    xcall_cpu_data_set_recv_call(cpu_data, NULL);
}

static int __init
xcall_setup(void)
{
    unsigned int i;

    for (i = 0; i < cpu_count(); i++) {
        xcall_cpu_data_init(percpu_ptr(xcall_cpu_data, i));
    }

    return 0;
}

INIT_OP_DEFINE(xcall_setup,
               INIT_OP_DEP(thread_bootstrap, true),
               INIT_OP_DEP(spinlock_setup, true));

void
xcall_call(xcall_fn_t fn, void *arg, unsigned int cpu)
{
    struct xcall_cpu_data *local_data, *remote_data;
    struct xcall *call;

    assert(cpu_intr_enabled());
    assert(fn != NULL);

    remote_data = percpu_ptr(xcall_cpu_data, cpu);

    thread_preempt_disable();

    local_data = xcall_cpu_data_get();
    call = xcall_cpu_data_get_send_call(local_data, cpu);
    xcall_set(call, fn, arg);

    spinlock_lock(&remote_data->lock);

    xcall_cpu_data_set_recv_call(remote_data, call);

    cpu_send_xcall(cpu);

    while (xcall_cpu_data_get_recv_call(remote_data) != NULL) {
        cpu_pause();
    }

    spinlock_unlock(&remote_data->lock);

    thread_preempt_enable();
}

void
xcall_intr(void)
{
    struct xcall_cpu_data *cpu_data;
    struct xcall *call;

    assert(thread_check_intr_context());

    cpu_data = xcall_cpu_data_get();
    call = xcall_cpu_data_get_recv_call(cpu_data);
    call->fn(call->arg);
    xcall_cpu_data_clear_recv_call(cpu_data);
}
