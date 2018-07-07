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
 */

#include <assert.h>
#include <errno.h>
#include <stdint.h>

#include <kern/clock.h>
#include <kern/init.h>
#include <kern/log.h>
#include <kern/macros.h>
#include <kern/perfmon.h>
#include <machine/cpu.h>
#include <machine/pmu_amd.h>

/*
 * AMD raw event IDs.
 */
#define PMU_AMD_RE_CYCLE            0
#define PMU_AMD_RE_INSTRUCTION      1
#define PMU_AMD_RE_CACHE_REF        2
#define PMU_AMD_RE_CACHE_MISS       3
#define PMU_AMD_RE_BRANCH           4
#define PMU_AMD_RE_BRANCH_MISS      5
#define PMU_AMD_RE_DCACHE_REF       6
#define PMU_AMD_RE_DCACHE_MISS      7
#define PMU_AMD_RE_IFETCH_STALL     8
#define PMU_AMD_RE_INVALID          ((unsigned int)-1)

/*
 * PMU MSR addresses
 */
#define PMU_AMD_MSR_PERFEVTSEL0 0xc0010000
#define PMU_AMD_MSR_PERCTR0     0xc0010004

/*
 * Event Select Register addresses
 */
#define PMU_AMD_EVTSEL_USR  0x00010000
#define PMU_AMD_EVTSEL_OS   0x00020000
#define PMU_AMD_EVTSEL_INT  0x00100000
#define PMU_AMD_EVTSEL_EN   0x00400000

/*
 * XXX These properties have the minimum values required by the architecture.
 * TODO Per-family/model event availability database.
 */
#define PMU_AMD_NR_PMCS     4
#define PMU_AMD_PMC_WIDTH   48

/*
 * Global PMU properties.
 *
 * The bitmap is used to implement counter allocation, where each bit denotes
 * whether a counter is available or not.
 */
struct pmu_amd {
    unsigned int pmc_bm;
};

static struct pmu_amd pmu_amd;

struct pmu_amd_event_code {
    unsigned short event_select;
    unsigned short umask;
};

/*
 * TODO Per-family/model event availability database.
 */
static const struct pmu_amd_event_code pmu_amd_event_codes[] = {
    [PMU_AMD_RE_CYCLE]          = { 0x76, 0x00 },
    [PMU_AMD_RE_INSTRUCTION]    = { 0xc0, 0x00 },
    [PMU_AMD_RE_CACHE_REF]      = { 0x80, 0x00 },
    [PMU_AMD_RE_CACHE_MISS]     = { 0x81, 0x00 },
    [PMU_AMD_RE_BRANCH]         = { 0xc2, 0x00 },
    [PMU_AMD_RE_BRANCH_MISS]    = { 0xc3, 0x00 },
    [PMU_AMD_RE_DCACHE_REF]     = { 0x40, 0x00 },
    [PMU_AMD_RE_DCACHE_MISS]    = { 0x41, 0x00 },
    [PMU_AMD_RE_IFETCH_STALL]   = { 0x87, 0x00 },
};

static const unsigned int pmu_amd_generic_events[] = {
    [PERFMON_EV_CYCLE]          = PMU_AMD_RE_CYCLE,
    [PERFMON_EV_REF_CYCLE]      = PMU_AMD_RE_INVALID,
    [PERFMON_EV_INSTRUCTION]    = PMU_AMD_RE_INSTRUCTION,
    [PERFMON_EV_CACHE_REF]      = PMU_AMD_RE_CACHE_REF,
    [PERFMON_EV_CACHE_MISS]     = PMU_AMD_RE_CACHE_MISS,
    [PERFMON_EV_BRANCH]         = PMU_AMD_RE_BRANCH,
    [PERFMON_EV_BRANCH_MISS]    = PMU_AMD_RE_BRANCH_MISS,
};

static struct pmu_amd *
pmu_amd_get(void)
{
    return &pmu_amd;
}

static int
pmu_amd_translate(unsigned int *raw_event_idp, unsigned int event_id)
{
    assert(event_id < ARRAY_SIZE(pmu_amd_generic_events));

    *raw_event_idp = pmu_amd_generic_events[event_id];
    return 0;
}

static int
pmu_amd_alloc(unsigned int *pmc_idp, unsigned int pmc_index,
              unsigned int raw_event_id)
{
    struct pmu_amd *pmu;
    unsigned int pmc_id;

    /* TODO Per-family/model event availability database */

    (void)pmc_index;
    (void)raw_event_id;

    pmu = pmu_amd_get();

    if (pmu->pmc_bm == 0) {
        return EAGAIN;
    }

    pmc_id = __builtin_ffs(pmu->pmc_bm) - 1;
    pmu->pmc_bm &= ~(1U << pmc_id);
    *pmc_idp = pmc_id;

    return 0;
}

static void
pmu_amd_free(unsigned int pmc_id)
{
    struct pmu_amd *pmu;
    unsigned int mask;

    assert(pmc_id < PMU_AMD_NR_PMCS);

    pmu = pmu_amd_get();
    mask = (1U << pmc_id);
    assert(!(pmu->pmc_bm & mask));
    pmu->pmc_bm |= mask;
}

static void
pmu_amd_start(unsigned int pmc_id, unsigned int raw_event_id)
{
    const struct pmu_amd_event_code *code;
    uint32_t high, low;

    assert(pmc_id < PMU_AMD_NR_PMCS);
    assert(raw_event_id < ARRAY_SIZE(pmu_amd_event_codes));

    code = &pmu_amd_event_codes[raw_event_id];

    /* TODO Handle PERFMON_EF_KERN/PERFMON_EF_USER */
    high = code->event_select >> 8;
    low = PMU_AMD_EVTSEL_EN
          | PMU_AMD_EVTSEL_OS
          | PMU_AMD_EVTSEL_USR
          | (code->umask << 8)
          | (code->event_select & 0xff);
    cpu_set_msr(PMU_AMD_MSR_PERFEVTSEL0 + pmc_id, high, low);
}

static void
pmu_amd_stop(unsigned int pmc_id)
{
    assert(pmc_id < PMU_AMD_NR_PMCS);

    cpu_set_msr(PMU_AMD_MSR_PERFEVTSEL0 + pmc_id, 0, 0);
}

static uint64_t
pmu_amd_read(unsigned int pmc_id)
{
    assert(pmc_id < PMU_AMD_NR_PMCS);

    return cpu_get_msr64(PMU_AMD_MSR_PERCTR0 + pmc_id);
}

static const struct perfmon_dev_ops pmu_amd_ops = {
    .translate  = pmu_amd_translate,
    .alloc      = pmu_amd_alloc,
    .free       = pmu_amd_free,
    .start      = pmu_amd_start,
    .stop       = pmu_amd_stop,
    .read       = pmu_amd_read,
};

static struct perfmon_dev pmu_amd_dev __read_mostly;

static int __init
pmu_amd_setup(void)
{
    const struct cpu *cpu;
    struct pmu_amd *pmu;

    cpu = cpu_current();

    if (cpu_vendor_id(cpu) != CPU_VENDOR_AMD) {
        return ENODEV;
    }

    if (cpu_family(cpu) < 0x10) {
        return ENODEV;
    }

    pmu = pmu_amd_get();
    pmu->pmc_bm = (1U << PMU_AMD_NR_PMCS) - 1;

    pmu_amd_dev.ops = &pmu_amd_ops;
    pmu_amd_dev.pmc_width = PMU_AMD_PMC_WIDTH;
    perfmon_register(&pmu_amd_dev);
    log_info("pmu: amd, nr_pmcs:%u pmc_width:%u",
             PMU_AMD_NR_PMCS, PMU_AMD_PMC_WIDTH);
    return 0;
}

INIT_OP_DEFINE(pmu_amd_setup,
               INIT_OP_DEP(cpu_setup, true),
               INIT_OP_DEP(log_setup, true),
               INIT_OP_DEP(perfmon_bootstrap, true));
