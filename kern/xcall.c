/*
 * Copyright (c) 2014-2018 Richard Braun.
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
#include <stdio.h>

#include <kern/atomic.h>
#include <kern/init.h>
#include <kern/log.h>
#include <kern/macros.h>
#include <kern/percpu.h>
#include <kern/spinlock.h>
#include <kern/syscnt.h>
#include <kern/thread.h>
#include <kern/xcall.h>
#include <machine/cpu.h>

struct xcall {
    xcall_fn_t fn;
    void *arg;
};

/*
 * Per-CPU data.
 *
 * The lock is used to serialize cross-calls from different processors
 * to the same processor. It is held during the complete cross-call
 * sequence. Inside the critical section, accesses to the receive call
 * are used to enforce release-acquire ordering between the sending
 * and receiving processors.
 *
 * Locking keys :
 * (a) atomic
 * (c) cpu_data
 */
struct xcall_cpu_data {
    alignas(CPU_L1_SIZE) struct spinlock lock;
    struct xcall *recv_call;    /* (c) */
    struct syscnt sc_sent;      /* (a) */
    struct syscnt sc_received;  /* (a) */
};

static struct xcall_cpu_data xcall_cpu_data __percpu;

static struct xcall_cpu_data *
xcall_get_local_cpu_data(void)
{
    return cpu_local_ptr(xcall_cpu_data);
}

static struct xcall_cpu_data *
xcall_get_cpu_data(unsigned int cpu)
{
    return percpu_ptr(xcall_cpu_data, cpu);
}

static void
xcall_init(struct xcall *call, xcall_fn_t fn, void *arg)
{
    call->fn = fn;
    call->arg = arg;
}

static void
xcall_process(struct xcall *call)
{
    call->fn(call->arg);
}

static void
xcall_cpu_data_init(struct xcall_cpu_data *cpu_data, unsigned int cpu)
{
    char name[SYSCNT_NAME_SIZE];

    snprintf(name, sizeof(name), "xcall_sent/%u", cpu);
    syscnt_register(&cpu_data->sc_sent, name);
    snprintf(name, sizeof(name), "xcall_received/%u", cpu);
    syscnt_register(&cpu_data->sc_received, name);
    cpu_data->recv_call = NULL;
    spinlock_init(&cpu_data->lock);
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
        xcall_cpu_data_init(xcall_get_cpu_data(i), i);
    }

    return 0;
}

INIT_OP_DEFINE(xcall_setup,
               INIT_OP_DEP(cpu_mp_probe, true),
               INIT_OP_DEP(thread_bootstrap, true),
               INIT_OP_DEP(spinlock_setup, true),
               INIT_OP_DEP(syscnt_setup, true));

void
xcall_call(xcall_fn_t fn, void *arg, unsigned int cpu)
{
    struct xcall_cpu_data *cpu_data;
    struct xcall call;

    assert(cpu_intr_enabled());
    assert(fn);

    xcall_init(&call, fn, arg);
    cpu_data = xcall_get_cpu_data(cpu);

    spinlock_lock(&cpu_data->lock);

    /* Enforce release ordering on the receive call */
    xcall_cpu_data_set_recv_call(cpu_data, &call);

    cpu_send_xcall(cpu);

    /* Enforce acquire ordering on the receive call */
    while (xcall_cpu_data_get_recv_call(cpu_data) != NULL) {
        cpu_pause();
    }

    spinlock_unlock(&cpu_data->lock);

    syscnt_inc(&cpu_data->sc_sent);
}

void
xcall_intr(void)
{
    struct xcall_cpu_data *cpu_data;
    struct xcall *call;

    assert(thread_check_intr_context());

    cpu_data = xcall_get_local_cpu_data();

    /* Enforce acquire ordering on the receive call */
    call = xcall_cpu_data_get_recv_call(cpu_data);

    if (call) {
        xcall_process(call);
    } else {
        log_err("xcall: spurious interrupt on cpu%u", cpu_id());
    }

    syscnt_inc(&cpu_data->sc_received);

    /* Enforce release ordering on the receive call */
    xcall_cpu_data_clear_recv_call(cpu_data);
}
