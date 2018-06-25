/*
 * Copyright (c) 2014-2018 Remy Noel.
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
 *
 *
 * Locking order :
 *
 *             thread_runq -+
 *                          |
 *   event -+-> interrupts -+-> td
 *          |
 *          +-> pmu
 *
 * TODO Kernel/user mode seggregation.
 */

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <kern/clock.h>
#include <kern/init.h>
#include <kern/list.h>
#include <kern/log.h>
#include <kern/macros.h>
#include <kern/percpu.h>
#include <kern/perfmon.h>
#include <kern/perfmon_types.h>
#include <kern/spinlock.h>
#include <kern/syscnt.h>
#include <kern/thread.h>
#include <kern/timer.h>
#include <kern/xcall.h>
#include <machine/boot.h>
#include <machine/cpu.h>

/*
 * Minimum hardware counter poll interval, in milliseconds.
 *
 * The main purpose of polling hardware counters is to detect overflows
 * when the driver is unable to reliably use overflow interrupts.
 */
#define PERFMON_MIN_POLL_INTERVAL 50

/*
 * Internal event flags.
 */
#define PERFMON_EF_TYPE_CPU         0x100
#define PERFMON_EF_ATTACHED         0x200
#define PERFMON_EF_PUBLIC_MASK      (PERFMON_EF_KERN \
                                     | PERFMON_EF_USER \
                                     | PERFMON_EF_RAW)

/*
 * Per-CPU performance monitoring counter.
 *
 * When an event is attached to a processor, the matching per-CPU PMC get
 * referenced. When a per-CPU PMC is referenced, its underlying hardware
 * counter is active.
 *
 * Interrupts and preemption must be disabled on access.
 */
struct perfmon_cpu_pmc {
    unsigned int nr_refs;
    unsigned int pmc_id;
    unsigned int raw_event_id;
    uint64_t raw_value;
    uint64_t value;
};

/*
 * Per-CPU performance monitoring unit.
 *
 * Per-CPU PMCs are indexed the same way as global PMCs.
 *
 * Interrupts and preemption must be disabled on access.
 */
struct perfmon_cpu_pmu {
    struct perfmon_dev *dev;
    unsigned int cpu;
    struct perfmon_cpu_pmc pmcs[PERFMON_MAX_PMCS];
    struct timer poll_timer;
    struct syscnt sc_nr_overflows;
};

/*
 * Performance monitoring counter.
 *
 * When a PMC is used, it maps a raw event to a hardware counter.
 * A PMC is used if and only if its reference counter isn't zero.
 */
struct perfmon_pmc {
    unsigned int nr_refs;
    unsigned int pmc_id;
    unsigned int raw_event_id;
};

/*
 * Performance monitoring unit.
 *
 * There is a single system-wide logical PMU, used to globally allocate
 * PMCs. Reserving a counter across the entire system ensures thread
 * migration isn't hindered by performance monitoring.
 *
 * Locking the global PMU is only required when allocating or releasing
 * a PMC. Once allocated, the PMC may safely be accessed without hodling
 * the lock.
 */
struct perfmon_pmu {
    struct perfmon_dev *dev;
    struct spinlock lock;
    struct perfmon_pmc pmcs[PERFMON_MAX_PMCS];
};

static struct perfmon_pmu perfmon_pmu;
static struct perfmon_cpu_pmu perfmon_cpu_pmu __percpu;

static struct perfmon_pmu *
perfmon_get_pmu(void)
{
    return &perfmon_pmu;
}

static struct perfmon_cpu_pmu *
perfmon_get_local_cpu_pmu(void)
{
    assert(!thread_preempt_enabled());
    return cpu_local_ptr(perfmon_cpu_pmu);
}

static struct perfmon_cpu_pmu *
perfmon_get_cpu_pmu(unsigned int cpu)
{
    return percpu_ptr(perfmon_cpu_pmu, cpu);
}

static void __init
perfmon_pmc_init(struct perfmon_pmc *pmc)
{
    pmc->nr_refs = 0;
}

static bool
perfmon_pmc_used(const struct perfmon_pmc *pmc)
{
    return pmc->nr_refs != 0;
}

static unsigned int
perfmon_pmc_id(const struct perfmon_pmc *pmc)
{
    return pmc->pmc_id;
}

static unsigned int
perfmon_pmc_raw_event_id(const struct perfmon_pmc *pmc)
{
    return pmc->raw_event_id;
}

static void
perfmon_pmc_use(struct perfmon_pmc *pmc, unsigned int pmc_id,
                unsigned int raw_event_id)
{
    assert(!perfmon_pmc_used(pmc));

    pmc->nr_refs = 1;
    pmc->pmc_id = pmc_id;
    pmc->raw_event_id = raw_event_id;
}

static void
perfmon_pmc_ref(struct perfmon_pmc *pmc)
{
    assert(perfmon_pmc_used(pmc));
    pmc->nr_refs++;
}

static void
perfmon_pmc_unref(struct perfmon_pmc *pmc)
{
    assert(perfmon_pmc_used(pmc));
    pmc->nr_refs--;
}

static unsigned int
perfmon_pmu_get_pmc_index(const struct perfmon_pmu *pmu,
                          const struct perfmon_pmc *pmc)
{
    size_t pmc_index;

    pmc_index = pmc - pmu->pmcs;
    assert(pmc_index < ARRAY_SIZE(pmu->pmcs));
    return pmc_index;
}

static struct perfmon_pmc *
perfmon_pmu_get_pmc(struct perfmon_pmu *pmu, unsigned int index)
{
    assert(index < ARRAY_SIZE(pmu->pmcs));
    return &pmu->pmcs[index];
}

static void __init
perfmon_pmu_init(struct perfmon_pmu *pmu)
{
    pmu->dev = NULL;
    spinlock_init(&pmu->lock);

    for (unsigned int i = 0; i < ARRAY_SIZE(pmu->pmcs); i++) {
        perfmon_pmc_init(perfmon_pmu_get_pmc(pmu, i));
    }
}

static void __init
perfmon_pmu_set_dev(struct perfmon_pmu *pmu, struct perfmon_dev *dev)
{
    assert(dev);
    assert(!pmu->dev);
    pmu->dev = dev;
}

static struct perfmon_dev *
perfmon_pmu_get_dev(const struct perfmon_pmu *pmu)
{
    return pmu->dev;
}

static void
perfmon_pmu_handle_overflow_intr(const struct perfmon_pmu *pmu)
{
    pmu->dev->ops->handle_overflow_intr();
}

static int
perfmon_pmu_translate(const struct perfmon_pmu *pmu,
                      unsigned int *raw_event_id,
                      unsigned int event_id)
{
    if (!pmu->dev) {
        return ENODEV;
    }

    return pmu->dev->ops->translate(raw_event_id, event_id);
}

static int
perfmon_pmu_alloc_pmc_id(const struct perfmon_pmu *pmu,
                         unsigned int *pmc_idp,
                         unsigned int pmc_index,
                         unsigned int raw_event_id)
{
    unsigned int pmc_id;
    int error;

    if (!pmu->dev) {
        return ENODEV;
    }

    error = pmu->dev->ops->alloc(&pmc_id, pmc_index, raw_event_id);

    if (error) {
        return error;
    }

    *pmc_idp = pmc_id;
    return 0;
}

static void
perfmon_pmu_free_pmc_id(const struct perfmon_pmu *pmu, unsigned int pmc_id)
{
    assert(pmu->dev);
    pmu->dev->ops->free(pmc_id);
}

static struct perfmon_pmc *
perfmon_pmu_find_unused_pmc(struct perfmon_pmu *pmu)
{
    struct perfmon_pmc *pmc;

    for (unsigned int i = 0; i < ARRAY_SIZE(pmu->pmcs); i++) {
        pmc = perfmon_pmu_get_pmc(pmu, i);

        if (!perfmon_pmc_used(pmc)) {
            return pmc;
        }
    }

    return NULL;
}

static int
perfmon_pmu_alloc_pmc(struct perfmon_pmu *pmu, struct perfmon_pmc **pmcp,
                      unsigned int raw_event_id)
{
    unsigned int pmc_id = 0, pmc_index;
    struct perfmon_pmc *pmc;
    int error;

    pmc = perfmon_pmu_find_unused_pmc(pmu);

    if (!pmc) {
        return EAGAIN;
    }

    pmc_index = perfmon_pmu_get_pmc_index(pmu, pmc);
    error = perfmon_pmu_alloc_pmc_id(pmu, &pmc_id, pmc_index, raw_event_id);

    if (error) {
        return error;
    }

    perfmon_pmc_use(pmc, pmc_id, raw_event_id);
    *pmcp = pmc;
    return 0;
}

static void
perfmon_pmu_free_pmc(struct perfmon_pmu *pmu, struct perfmon_pmc *pmc)
{
    unsigned int pmc_id;

    assert(!perfmon_pmc_used(pmc));
    pmc_id = perfmon_pmc_id(pmc);
    perfmon_pmu_free_pmc_id(pmu, pmc_id);
}

static struct perfmon_pmc *
perfmon_pmu_get_pmc_by_raw_event_id(struct perfmon_pmu *pmu,
                                    unsigned int raw_event_id)
{
    struct perfmon_pmc *pmc;

    for (unsigned int i = 0; i < ARRAY_SIZE(pmu->pmcs); i++) {
        pmc = perfmon_pmu_get_pmc(pmu, i);

        if (!perfmon_pmc_used(pmc)) {
            continue;
        }

        if (perfmon_pmc_raw_event_id(pmc) == raw_event_id) {
            return pmc;
        }
    }

    return NULL;
}

static int
perfmon_pmu_take_pmc(struct perfmon_pmu *pmu, struct perfmon_pmc **pmcp,
                     unsigned int raw_event_id)
{
    struct perfmon_pmc *pmc;
    int error;

    spinlock_lock(&pmu->lock);

    pmc = perfmon_pmu_get_pmc_by_raw_event_id(pmu, raw_event_id);

    if (pmc) {
        perfmon_pmc_ref(pmc);
        error = 0;
    } else {
        error = perfmon_pmu_alloc_pmc(pmu, &pmc, raw_event_id);

        if (error) {
            pmc = NULL;
        }
    }

    spinlock_unlock(&pmu->lock);

    if (error) {
        return error;
    }

    *pmcp = pmc;
    return 0;
}

static void
perfmon_pmu_put_pmc(struct perfmon_pmu *pmu, struct perfmon_pmc *pmc)
{
    spinlock_lock(&pmu->lock);

    perfmon_pmc_unref(pmc);

    if (!perfmon_pmc_used(pmc)) {
        perfmon_pmu_free_pmc(pmu, pmc);
    }

    spinlock_unlock(&pmu->lock);
}

static int
perfmon_check_event_args(unsigned int id, unsigned int flags)
{
    if (!((flags & PERFMON_EF_PUBLIC_MASK) == flags)
        || !((flags & PERFMON_EF_RAW) || (id < PERFMON_NR_GENERIC_EVENTS))
        || !((flags & (PERFMON_EF_KERN | PERFMON_EF_USER)))) {
        return EINVAL;
    }

    return 0;
}

int
perfmon_event_init(struct perfmon_event *event, unsigned int id,
                   unsigned int flags)
{
    int error;

    error = perfmon_check_event_args(id, flags);

    if (error) {
        return error;
    }

    spinlock_init(&event->lock);
    event->flags = flags;
    event->id = id;
    event->value = 0;
    return 0;
}

static bool
perfmon_event_type_cpu(const struct perfmon_event *event)
{
    return event->flags & PERFMON_EF_TYPE_CPU;
}

static void
perfmon_event_set_type_cpu(struct perfmon_event *event)
{
    event->flags |= PERFMON_EF_TYPE_CPU;
}

static void
perfmon_event_clear_type_cpu(struct perfmon_event *event)
{
    event->flags &= ~PERFMON_EF_TYPE_CPU;
}

static bool
perfmon_event_attached(const struct perfmon_event *event)
{
    return event->flags & PERFMON_EF_ATTACHED;
}

static unsigned int
perfmon_event_pmc_index(const struct perfmon_event *event)
{
    assert(perfmon_event_attached(event));
    return event->pmc_index;
}

static void __init
perfmon_cpu_pmc_init(struct perfmon_cpu_pmc *cpu_pmc)
{
    cpu_pmc->nr_refs = 0;
}

static bool
perfmon_cpu_pmc_used(const struct perfmon_cpu_pmc *cpu_pmc)
{
    return cpu_pmc->nr_refs != 0;
}

static void
perfmon_cpu_pmc_use(struct perfmon_cpu_pmc *cpu_pmc, unsigned int pmc_id,
                    unsigned int raw_event_id, uint64_t raw_value)
{
    assert(!perfmon_cpu_pmc_used(cpu_pmc));

    cpu_pmc->nr_refs = 1;
    cpu_pmc->pmc_id = pmc_id;
    cpu_pmc->raw_event_id = raw_event_id;
    cpu_pmc->raw_value = raw_value;
    cpu_pmc->value = 0;
}

static void
perfmon_cpu_pmc_ref(struct perfmon_cpu_pmc *cpu_pmc)
{
    assert(perfmon_cpu_pmc_used(cpu_pmc));
    cpu_pmc->nr_refs++;
}

static void
perfmon_cpu_pmc_unref(struct perfmon_cpu_pmc *cpu_pmc)
{
    assert(perfmon_cpu_pmc_used(cpu_pmc));
    cpu_pmc->nr_refs--;
}

static unsigned int
perfmon_cpu_pmc_id(const struct perfmon_cpu_pmc *cpu_pmc)
{
    return cpu_pmc->pmc_id;
}

static bool
perfmon_cpu_pmc_update(struct perfmon_cpu_pmc *cpu_pmc, uint64_t raw_value,
                       unsigned int pmc_width)
{
    bool overflowed;
    uint64_t delta;

    delta = raw_value - cpu_pmc->raw_value;

    if (pmc_width == 64) {
        overflowed = false;
    } else {
        if (raw_value >= cpu_pmc->raw_value) {
            overflowed = false;
        } else {
            overflowed = true;
            delta += (uint64_t)1 << pmc_width;
        }
    }

    cpu_pmc->value += delta;
    cpu_pmc->raw_value = raw_value;
    return overflowed;
}

static uint64_t
perfmon_cpu_pmc_get_value(const struct perfmon_cpu_pmc *cpu_pmc)
{
    return cpu_pmc->value;
}

static struct perfmon_cpu_pmc *
perfmon_cpu_pmu_get_pmc(struct perfmon_cpu_pmu *cpu_pmu, unsigned int index)
{
    assert(index < ARRAY_SIZE(cpu_pmu->pmcs));
    return &cpu_pmu->pmcs[index];
}

static void
perfmon_cpu_pmu_start(struct perfmon_cpu_pmu *cpu_pmu, unsigned int pmc_id,
                      unsigned int raw_event_id)
{
    cpu_pmu->dev->ops->start(pmc_id, raw_event_id);
}

static void
perfmon_cpu_pmu_stop(struct perfmon_cpu_pmu *cpu_pmu, unsigned int pmc_id)
{
    cpu_pmu->dev->ops->stop(pmc_id);
}

static uint64_t
perfmon_cpu_pmu_read(const struct perfmon_cpu_pmu *cpu_pmu, unsigned int pmc_id)
{
    return cpu_pmu->dev->ops->read(pmc_id);
}

static void
perfmon_cpu_pmu_use_pmc(struct perfmon_cpu_pmu *cpu_pmu,
                        struct perfmon_cpu_pmc *cpu_pmc,
                        unsigned int pmc_id,
                        unsigned int raw_event_id)
{
    uint64_t raw_value;

    perfmon_cpu_pmu_start(cpu_pmu, pmc_id, raw_event_id);
    raw_value = perfmon_cpu_pmu_read(cpu_pmu, pmc_id);
    perfmon_cpu_pmc_use(cpu_pmc, pmc_id, raw_event_id, raw_value);
}

static void
perfmon_cpu_pmu_update_pmc(struct perfmon_cpu_pmu *cpu_pmu,
                           struct perfmon_cpu_pmc *cpu_pmc)
{
    uint64_t raw_value;
    bool overflowed;

    raw_value = perfmon_cpu_pmu_read(cpu_pmu, perfmon_cpu_pmc_id(cpu_pmc));
    overflowed = perfmon_cpu_pmc_update(cpu_pmc, raw_value,
                                        cpu_pmu->dev->pmc_width);

    if (overflowed) {
        syscnt_inc(&cpu_pmu->sc_nr_overflows);
    }
}

static void
perfmon_cpu_pmu_check_overflow(void *arg)
{
    struct perfmon_cpu_pmu *cpu_pmu;
    struct perfmon_cpu_pmc *cpu_pmc;

    assert(!cpu_intr_enabled());

    cpu_pmu = arg;
    assert(cpu_pmu->cpu == cpu_id());

    for (unsigned int i = 0; i < ARRAY_SIZE(cpu_pmu->pmcs); i++) {
        cpu_pmc = perfmon_cpu_pmu_get_pmc(cpu_pmu, i);

        if (!perfmon_cpu_pmc_used(cpu_pmc)) {
            continue;
        }

        perfmon_cpu_pmu_update_pmc(cpu_pmu, cpu_pmc);
    }
}

static void
perfmon_cpu_pmu_poll(struct timer *timer)
{
    struct perfmon_cpu_pmu *cpu_pmu;

    cpu_pmu = structof(timer, struct perfmon_cpu_pmu, poll_timer);
    xcall_call(perfmon_cpu_pmu_check_overflow, cpu_pmu, cpu_pmu->cpu);
    timer_schedule(timer, timer_get_time(timer) + cpu_pmu->dev->poll_interval);
}

static void __init
perfmon_cpu_pmu_init(struct perfmon_cpu_pmu *cpu_pmu, unsigned int cpu,
                     struct perfmon_dev *dev)
{
    char name[SYSCNT_NAME_SIZE];

    cpu_pmu->dev = dev;
    cpu_pmu->cpu = cpu;

    for (unsigned int i = 0; i < ARRAY_SIZE(cpu_pmu->pmcs); i++) {
        perfmon_cpu_pmc_init(perfmon_cpu_pmu_get_pmc(cpu_pmu, i));
    }

    if (dev->ops->handle_overflow_intr == NULL) {
        assert(dev->poll_interval != 0);

        /*
         * XXX Ideally, this would be an interrupt timer instead of a high
         * priority one, but it can't be because the handler performs
         * cross-calls to remote processors, which requires that interrupts
         * be enabled. This is one potential user of CPU-bound timers.
         */
        timer_init(&cpu_pmu->poll_timer, perfmon_cpu_pmu_poll, TIMER_HIGH_PRIO);
        timer_schedule(&cpu_pmu->poll_timer, dev->poll_interval);
    }

    snprintf(name, sizeof(name), "perfmon_nr_overflows/%u", cpu);
    syscnt_register(&cpu_pmu->sc_nr_overflows, name);
}

static uint64_t
perfmon_cpu_pmu_load(struct perfmon_cpu_pmu *cpu_pmu, unsigned int pmc_index,
                     unsigned int pmc_id, unsigned int raw_event_id)
{
    struct perfmon_cpu_pmc *cpu_pmc;

    assert(!cpu_intr_enabled());

    cpu_pmc = perfmon_cpu_pmu_get_pmc(cpu_pmu, pmc_index);

    if (perfmon_cpu_pmc_used(cpu_pmc)) {
        perfmon_cpu_pmc_ref(cpu_pmc);
        perfmon_cpu_pmu_update_pmc(cpu_pmu, cpu_pmc);
    } else {
        perfmon_cpu_pmu_use_pmc(cpu_pmu, cpu_pmc, pmc_id, raw_event_id);
    }

    return perfmon_cpu_pmc_get_value(cpu_pmc);
}

static uint64_t
perfmon_cpu_pmu_unload(struct perfmon_cpu_pmu *cpu_pmu, unsigned int pmc_index)
{
    struct perfmon_cpu_pmc *cpu_pmc;
    unsigned int pmc_id;
    uint64_t value;

    assert(!cpu_intr_enabled());

    cpu_pmc = perfmon_cpu_pmu_get_pmc(cpu_pmu, pmc_index);
    pmc_id = perfmon_cpu_pmc_id(cpu_pmc);

    perfmon_cpu_pmu_update_pmc(cpu_pmu, cpu_pmc);
    value = perfmon_cpu_pmc_get_value(cpu_pmc);

    perfmon_cpu_pmc_unref(cpu_pmc);

    if (!perfmon_cpu_pmc_used(cpu_pmc)) {
        perfmon_cpu_pmu_stop(cpu_pmu, pmc_id);
    }

    return value;
}

static uint64_t
perfmon_cpu_pmu_sync(struct perfmon_cpu_pmu *cpu_pmu, unsigned int pmc_index)
{
    struct perfmon_cpu_pmc *cpu_pmc;

    assert(!cpu_intr_enabled());

    cpu_pmc = perfmon_cpu_pmu_get_pmc(cpu_pmu, pmc_index);
    perfmon_cpu_pmu_update_pmc(cpu_pmu, cpu_pmc);
    return perfmon_cpu_pmc_get_value(cpu_pmc);
}

static void
perfmon_td_pmc_init(struct perfmon_td_pmc *td_pmc)
{
    td_pmc->nr_refs = 0;
    td_pmc->loaded = false;
    td_pmc->value = 0;
}

static bool
perfmon_td_pmc_used(const struct perfmon_td_pmc *td_pmc)
{
    return td_pmc->nr_refs != 0;
}

static void
perfmon_td_pmc_use(struct perfmon_td_pmc *td_pmc, unsigned int pmc_id,
                   unsigned int raw_event_id)
{
    assert(!perfmon_td_pmc_used(td_pmc));

    td_pmc->nr_refs = 1;
    td_pmc->loaded = false;
    td_pmc->pmc_id = pmc_id;
    td_pmc->raw_event_id = raw_event_id;
    td_pmc->value = 0;
}

static unsigned int
perfmon_td_pmc_id(const struct perfmon_td_pmc *td_pmc)
{
    return td_pmc->pmc_id;
}

static unsigned int
perfmon_td_pmc_raw_event_id(const struct perfmon_td_pmc *td_pmc)
{
    return td_pmc->raw_event_id;
}

static void
perfmon_td_pmc_ref(struct perfmon_td_pmc *td_pmc)
{
    assert(perfmon_td_pmc_used(td_pmc));
    td_pmc->nr_refs++;
}

static void
perfmon_td_pmc_unref(struct perfmon_td_pmc *td_pmc)
{
    assert(perfmon_td_pmc_used(td_pmc));
    td_pmc->nr_refs--;
}

static bool
perfmon_td_pmc_loaded(const struct perfmon_td_pmc *td_pmc)
{
    return td_pmc->loaded;
}

static void
perfmon_td_pmc_load(struct perfmon_td_pmc *td_pmc, uint64_t cpu_pmc_value)
{
    assert(!perfmon_td_pmc_loaded(td_pmc));

    td_pmc->cpu_pmc_value = cpu_pmc_value;
    td_pmc->loaded = true;
}

static void
perfmon_td_pmc_update(struct perfmon_td_pmc *td_pmc, uint64_t cpu_pmc_value)
{
    uint64_t delta;

    assert(perfmon_td_pmc_loaded(td_pmc));

    delta = cpu_pmc_value - td_pmc->cpu_pmc_value;
    td_pmc->cpu_pmc_value = cpu_pmc_value;
    td_pmc->value += delta;
}

static void
perfmon_td_pmc_unload(struct perfmon_td_pmc *td_pmc, uint64_t cpu_pmc_value)
{
    perfmon_td_pmc_update(td_pmc, cpu_pmc_value);
    td_pmc->loaded = false;
}

static uint64_t
perfmon_td_pmc_read(const struct perfmon_td_pmc *td_pmc)
{
    return td_pmc->value;
}

static unsigned int
perfmon_td_get_pmc_index(const struct perfmon_td *td,
                         const struct perfmon_td_pmc *td_pmc)
{
    size_t pmc_index;

    pmc_index = td_pmc - td->pmcs;
    assert(pmc_index < ARRAY_SIZE(td->pmcs));
    return pmc_index;
}

static struct perfmon_td_pmc *
perfmon_td_get_pmc(struct perfmon_td *td, unsigned int index)
{
    assert(index < ARRAY_SIZE(td->pmcs));
    return &td->pmcs[index];
}

void
perfmon_td_init(struct perfmon_td *td)
{
    spinlock_init(&td->lock);

    for (unsigned int i = 0; i < ARRAY_SIZE(td->pmcs); i++) {
        perfmon_td_pmc_init(perfmon_td_get_pmc(td, i));
    }
}

static void
perfmon_td_load_pmc(struct perfmon_td *td, struct perfmon_td_pmc *td_pmc)
{
    unsigned int pmc_index, pmc_id, raw_event_id;
    struct perfmon_cpu_pmu *cpu_pmu;
    uint64_t cpu_pmc_value;

    cpu_pmu = perfmon_get_local_cpu_pmu();
    pmc_index = perfmon_td_get_pmc_index(td, td_pmc);
    pmc_id = perfmon_td_pmc_id(td_pmc);
    raw_event_id = perfmon_td_pmc_raw_event_id(td_pmc);
    cpu_pmc_value = perfmon_cpu_pmu_load(cpu_pmu, pmc_index,
                                         pmc_id, raw_event_id);
    perfmon_td_pmc_load(td_pmc, cpu_pmc_value);
}

static void
perfmon_td_unload_pmc(struct perfmon_td *td, struct perfmon_td_pmc *td_pmc)
{
    struct perfmon_cpu_pmu *cpu_pmu;
    unsigned int pmc_index;
    uint64_t cpu_pmc_value;

    cpu_pmu = perfmon_get_local_cpu_pmu();
    pmc_index = perfmon_td_get_pmc_index(td, td_pmc);
    cpu_pmc_value = perfmon_cpu_pmu_unload(cpu_pmu, pmc_index);
    perfmon_td_pmc_unload(td_pmc, cpu_pmc_value);
}

static void
perfmon_td_update_pmc(struct perfmon_td *td, struct perfmon_td_pmc *td_pmc)
{
    struct perfmon_cpu_pmu *cpu_pmu;
    unsigned int pmc_index;
    uint64_t cpu_pmc_value;

    cpu_pmu = perfmon_get_local_cpu_pmu();
    pmc_index = perfmon_td_get_pmc_index(td, td_pmc);
    cpu_pmc_value = perfmon_cpu_pmu_sync(cpu_pmu, pmc_index);
    perfmon_td_pmc_update(td_pmc, cpu_pmc_value);
}

void
perfmon_td_load(struct perfmon_td *td)
{
    unsigned int pmc_index, pmc_id, raw_event_id;
    struct perfmon_cpu_pmu *cpu_pmu;
    struct perfmon_td_pmc *td_pmc;
    uint64_t cpu_pmc_value;

    assert(!cpu_intr_enabled());
    assert(!thread_preempt_enabled());

    cpu_pmu = perfmon_get_local_cpu_pmu();

    spinlock_lock(&td->lock);

    for (unsigned int i = 0; i < ARRAY_SIZE(td->pmcs); i++) {
        td_pmc = perfmon_td_get_pmc(td, i);

        if (!perfmon_td_pmc_used(td_pmc) || perfmon_td_pmc_loaded(td_pmc)) {
            continue;
        }

        pmc_index = perfmon_td_get_pmc_index(td, td_pmc);
        pmc_id = perfmon_td_pmc_id(td_pmc);
        raw_event_id = perfmon_td_pmc_raw_event_id(td_pmc);
        cpu_pmc_value = perfmon_cpu_pmu_load(cpu_pmu, pmc_index,
                                             pmc_id, raw_event_id);
        perfmon_td_pmc_load(td_pmc, cpu_pmc_value);
    }

    spinlock_unlock(&td->lock);
}

void
perfmon_td_unload(struct perfmon_td *td)
{
    struct perfmon_cpu_pmu *cpu_pmu;
    struct perfmon_td_pmc *td_pmc;
    unsigned int pmc_index;
    uint64_t cpu_pmc_value;

    assert(!cpu_intr_enabled());
    assert(!thread_preempt_enabled());

    cpu_pmu = perfmon_get_local_cpu_pmu();

    spinlock_lock(&td->lock);

    for (unsigned int i = 0; i < ARRAY_SIZE(td->pmcs); i++) {
        td_pmc = perfmon_td_get_pmc(td, i);

        if (!perfmon_td_pmc_loaded(td_pmc)) {
            continue;
        }

        pmc_index = perfmon_td_get_pmc_index(td, td_pmc);
        cpu_pmc_value = perfmon_cpu_pmu_unload(cpu_pmu, pmc_index);
        perfmon_td_pmc_unload(td_pmc, cpu_pmc_value);
    }

    spinlock_unlock(&td->lock);
}

static void
perfmon_event_load(struct perfmon_event *event, uint64_t pmc_value)
{
    event->pmc_value = pmc_value;
}

static void
perfmon_event_update(struct perfmon_event *event, uint64_t pmc_value)
{
    uint64_t delta;

    delta = pmc_value - event->pmc_value;
    event->value += delta;
    event->pmc_value = pmc_value;
}

static void
perfmon_event_load_cpu_remote(void *arg)
{
    struct perfmon_event *event;
    struct perfmon_cpu_pmu *cpu_pmu;
    const struct perfmon_pmc *pmc;
    struct perfmon_pmu *pmu;
    unsigned int pmc_index;
    uint64_t cpu_pmc_value;

    event = arg;
    cpu_pmu = perfmon_get_local_cpu_pmu();
    pmu = perfmon_get_pmu();
    pmc_index = perfmon_event_pmc_index(event);
    pmc = perfmon_pmu_get_pmc(pmu, pmc_index);
    cpu_pmc_value = perfmon_cpu_pmu_load(cpu_pmu, pmc_index,
                                         perfmon_pmc_id(pmc),
                                         perfmon_pmc_raw_event_id(pmc));
    perfmon_event_load(event, cpu_pmc_value);
}

static void
perfmon_event_load_cpu(struct perfmon_event *event, unsigned int cpu)
{
    perfmon_event_set_type_cpu(event);
    event->cpu = cpu;
    xcall_call(perfmon_event_load_cpu_remote, event, cpu);
}

static void
perfmon_event_load_thread_remote(void *arg)
{
    struct perfmon_event *event;
    struct perfmon_td_pmc *td_pmc;
    struct perfmon_td *td;
    unsigned int pmc_index;
    uint64_t td_pmc_value;

    event = arg;
    pmc_index = perfmon_event_pmc_index(event);
    td = thread_get_perfmon_td(event->thread);
    td_pmc = perfmon_td_get_pmc(td, pmc_index);

    spinlock_lock(&td->lock);

    if (thread_self() == event->thread) {

        if (perfmon_td_pmc_loaded(td_pmc)) {
            perfmon_td_update_pmc(td, td_pmc);
        } else {
            perfmon_td_load_pmc(td, td_pmc);
        }
    }

    td_pmc_value = perfmon_td_pmc_read(td_pmc);

    spinlock_unlock(&td->lock);

    perfmon_event_load(event, td_pmc_value);
}

static void
perfmon_event_load_thread(struct perfmon_event *event, struct thread *thread)
{
    struct perfmon_td_pmc *td_pmc;
    struct perfmon_td *td;
    struct perfmon_pmu *pmu;
    const struct perfmon_pmc *pmc;
    unsigned int pmc_index;
    unsigned long flags;

    pmu = perfmon_get_pmu();

    thread_ref(thread);
    event->thread = thread;

    pmc_index = perfmon_event_pmc_index(event);
    pmc = perfmon_pmu_get_pmc(pmu, pmc_index);
    td = thread_get_perfmon_td(thread);
    td_pmc = perfmon_td_get_pmc(td, pmc_index);

    spinlock_lock_intr_save(&td->lock, &flags);

    if (perfmon_td_pmc_used(td_pmc)) {
        perfmon_td_pmc_ref(td_pmc);
    } else {
        perfmon_td_pmc_use(td_pmc, perfmon_pmc_id(pmc),
                           perfmon_pmc_raw_event_id(pmc));
    }

    spinlock_unlock_intr_restore(&td->lock, flags);

    xcall_call(perfmon_event_load_thread_remote, event, thread_cpu(thread));
}

static void
perfmon_event_unload_cpu_remote(void *arg)
{
    struct perfmon_event *event;
    struct perfmon_cpu_pmu *cpu_pmu;
    unsigned int pmc_index;
    uint64_t cpu_pmc_value;

    event = arg;
    cpu_pmu = perfmon_get_local_cpu_pmu();
    pmc_index = perfmon_event_pmc_index(event);
    cpu_pmc_value = perfmon_cpu_pmu_unload(cpu_pmu, pmc_index);
    perfmon_event_update(event, cpu_pmc_value);
}

static void
perfmon_event_unload_cpu(struct perfmon_event *event)
{
    xcall_call(perfmon_event_unload_cpu_remote, event, event->cpu);
    perfmon_event_clear_type_cpu(event);
}

static void
perfmon_event_unload_thread_remote(void *arg)
{
    struct perfmon_event *event;
    struct perfmon_td_pmc *td_pmc;
    struct perfmon_td *td;
    unsigned int pmc_index;
    uint64_t td_pmc_value;

    event = arg;
    pmc_index = perfmon_event_pmc_index(event);
    td = thread_get_perfmon_td(event->thread);
    td_pmc = perfmon_td_get_pmc(td, pmc_index);

    spinlock_lock(&td->lock);

    if ((thread_self() == event->thread) && perfmon_td_pmc_loaded(td_pmc)) {
        if (perfmon_td_pmc_used(td_pmc)) {
            perfmon_td_update_pmc(td, td_pmc);
        } else {
            perfmon_td_unload_pmc(td, td_pmc);
        }
    }

    td_pmc_value = perfmon_td_pmc_read(td_pmc);

    spinlock_unlock(&td->lock);

    perfmon_event_update(event, td_pmc_value);
}

static void
perfmon_event_unload_thread(struct perfmon_event *event)
{
    struct perfmon_td_pmc *td_pmc;
    struct perfmon_td *td;
    unsigned int pmc_index;
    unsigned long flags;

    pmc_index = perfmon_event_pmc_index(event);
    td = thread_get_perfmon_td(event->thread);
    td_pmc = perfmon_td_get_pmc(td, pmc_index);

    spinlock_lock_intr_save(&td->lock, &flags);
    perfmon_td_pmc_unref(td_pmc);
    spinlock_unlock_intr_restore(&td->lock, flags);

    xcall_call(perfmon_event_unload_thread_remote, event,
               thread_cpu(event->thread));

    thread_unref(event->thread);
    event->thread = NULL;
}

static void
perfmon_event_sync_cpu_remote(void *arg)
{
    struct perfmon_event *event;
    struct perfmon_cpu_pmu *cpu_pmu;
    unsigned int pmc_index;
    uint64_t cpu_pmc_value;

    event = arg;
    cpu_pmu = perfmon_get_local_cpu_pmu();
    pmc_index = perfmon_event_pmc_index(event);
    cpu_pmc_value = perfmon_cpu_pmu_sync(cpu_pmu, pmc_index);
    perfmon_event_update(event, cpu_pmc_value);
}

static void
perfmon_event_sync_cpu(struct perfmon_event *event)
{
    xcall_call(perfmon_event_sync_cpu_remote, event, event->cpu);
}

static void
perfmon_event_sync_thread_remote(void *arg)
{
    struct perfmon_event *event;
    struct perfmon_td_pmc *td_pmc;
    struct perfmon_td *td;
    unsigned int pmc_index;
    uint64_t td_pmc_value;

    event = arg;
    pmc_index = perfmon_event_pmc_index(event);
    td = thread_get_perfmon_td(event->thread);
    td_pmc = perfmon_td_get_pmc(td, pmc_index);

    spinlock_lock(&td->lock);

    if (thread_self() == event->thread) {
        perfmon_td_update_pmc(td, td_pmc);
    }

    td_pmc_value = perfmon_td_pmc_read(td_pmc);

    spinlock_unlock(&td->lock);

    perfmon_event_update(event, td_pmc_value);
}

static void
perfmon_event_sync_thread(struct perfmon_event *event)
{
    xcall_call(perfmon_event_sync_thread_remote, event,
               thread_cpu(event->thread));
}

static int
perfmon_event_attach_pmu(struct perfmon_event *event)
{
    unsigned int raw_event_id = 0;
    struct perfmon_pmu *pmu;
    struct perfmon_pmc *pmc;
    int error;

    pmu = perfmon_get_pmu();

    if (!(event->flags & PERFMON_EF_RAW)) {
        error = perfmon_pmu_translate(pmu, &raw_event_id, event->id);

        if (error) {
            return error;
        }
    }

    error = perfmon_pmu_take_pmc(pmu, &pmc, raw_event_id);

    if (error) {
        return error;
    }

    event->pmc_index = perfmon_pmu_get_pmc_index(pmu, pmc);
    event->flags |= PERFMON_EF_ATTACHED;
    event->value = 0;
    return 0;
}

static void
perfmon_event_detach_pmu(struct perfmon_event *event)
{
    struct perfmon_pmu *pmu;
    struct perfmon_pmc *pmc;

    pmu = perfmon_get_pmu();
    pmc = perfmon_pmu_get_pmc(pmu, perfmon_event_pmc_index(event));
    perfmon_pmu_put_pmc(pmu, pmc);
    event->flags &= ~PERFMON_EF_ATTACHED;
}

int
perfmon_event_attach(struct perfmon_event *event, struct thread *thread)
{
    int error;

    spinlock_lock(&event->lock);

    if (perfmon_event_attached(event)) {
        error = EINVAL;
        goto error;
    }

    error = perfmon_event_attach_pmu(event);

    if (error) {
        goto error;
    }

    perfmon_event_load_thread(event, thread);

    spinlock_unlock(&event->lock);

    return 0;

error:
    spinlock_unlock(&event->lock);

    return error;
}

int
perfmon_event_attach_cpu(struct perfmon_event *event, unsigned int cpu)
{
    int error;

    if (cpu >= cpu_count()) {
        return EINVAL;
    }

    spinlock_lock(&event->lock);

    if (perfmon_event_attached(event)) {
        error = EINVAL;
        goto out;
    }

    error = perfmon_event_attach_pmu(event);

    if (error) {
        goto out;
    }

    perfmon_event_load_cpu(event, cpu);
    error = 0;

out:
    spinlock_unlock(&event->lock);

    return error;
}

int
perfmon_event_detach(struct perfmon_event *event)
{
    int error;

    spinlock_lock(&event->lock);

    if (!perfmon_event_attached(event)) {
        error = EINVAL;
        goto out;
    }

    if (perfmon_event_type_cpu(event)) {
        perfmon_event_unload_cpu(event);
    } else {
        perfmon_event_unload_thread(event);
    }

    perfmon_event_detach_pmu(event);
    error = 0;

out:
    spinlock_unlock(&event->lock);

    return error;
}

uint64_t
perfmon_event_read(struct perfmon_event *event)
{
    uint64_t value;

    spinlock_lock(&event->lock);

    if (perfmon_event_attached(event)) {
        if (perfmon_event_type_cpu(event)) {
            perfmon_event_sync_cpu(event);
        } else {
            perfmon_event_sync_thread(event);
        }
    }

    value = event->value;

    spinlock_unlock(&event->lock);

    return value;
}

static uint64_t __init
perfmon_compute_poll_interval(uint64_t pmc_width)
{
    uint64_t cycles, time;

    if (pmc_width == 64) {
        cycles = (uint64_t)-1;
    } else {
        cycles = (uint64_t)1 << pmc_width;
    }

    /*
     * Assume an unrealistically high upper bound on the number of
     * events per cycle to otbain a comfortable margin of safety.
     */
    cycles /= 100;
    time = cycles / (cpu_get_freq() / 1000);

    if (time < PERFMON_MIN_POLL_INTERVAL) {
        log_warning("perfmon: invalid poll interval %llu, forced to %llu",
                    (unsigned long long)time,
                    (unsigned long long)PERFMON_MIN_POLL_INTERVAL);
        time = PERFMON_MIN_POLL_INTERVAL;
    }

    return clock_ticks_from_ms(time);
}

void __init
perfmon_register(struct perfmon_dev *dev)
{
    const struct perfmon_dev_ops *ops;

    ops = dev->ops;
    assert(ops->translate && ops->alloc && ops->free
           && ops->start && ops->stop && ops->read);
    assert(dev->pmc_width <= 64);

    if ((dev->ops->handle_overflow_intr == NULL) && (dev->poll_interval == 0)) {
        dev->poll_interval = perfmon_compute_poll_interval(dev->pmc_width);
    }

    perfmon_pmu_set_dev(perfmon_get_pmu(), dev);
}

void
perfmon_overflow_intr(void)
{
    perfmon_pmu_handle_overflow_intr(perfmon_get_pmu());
}

void
perfmon_report_overflow(unsigned int pmc_index)
{
    struct perfmon_cpu_pmu *cpu_pmu;
    struct perfmon_cpu_pmc *cpu_pmc;

    assert(!cpu_intr_enabled());
    assert(!thread_preempt_enabled());

    cpu_pmu = perfmon_get_local_cpu_pmu();
    cpu_pmc = perfmon_cpu_pmu_get_pmc(cpu_pmu, pmc_index);
    perfmon_cpu_pmu_update_pmc(cpu_pmu, cpu_pmc);
}

static int __init
perfmon_bootstrap(void)
{
    perfmon_pmu_init(perfmon_get_pmu());
    return 0;
}

INIT_OP_DEFINE(perfmon_bootstrap,
               INIT_OP_DEP(log_setup, true),
               INIT_OP_DEP(spinlock_setup, true));

static int __init
perfmon_setup(void)
{
    struct perfmon_dev *dev;

    dev = perfmon_pmu_get_dev(perfmon_get_pmu());

    if (!dev) {
        return ENODEV;
    }

    for (unsigned int cpu = 0; cpu < cpu_count(); cpu++) {
        perfmon_cpu_pmu_init(perfmon_get_cpu_pmu(cpu), cpu, dev);
    }

    return 0;
}

INIT_OP_DEFINE(perfmon_setup,
               INIT_OP_DEP(boot_setup_pmu, true),
               INIT_OP_DEP(cpu_mp_probe, true),
               INIT_OP_DEP(cpu_setup, true),
               INIT_OP_DEP(percpu_setup, true),
               INIT_OP_DEP(perfmon_bootstrap, true),
               INIT_OP_DEP(spinlock_setup, true),
               INIT_OP_DEP(syscnt_setup, true));
