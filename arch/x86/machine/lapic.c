/*
 * Copyright (c) 2011-2017 Richard Braun.
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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <kern/assert.h>
#include <kern/init.h>
#include <kern/macros.h>
#include <kern/panic.h>
#include <kern/param.h>
#include <kern/thread.h>
#include <machine/cpu.h>
#include <machine/lapic.h>
#include <machine/pmap.h>
#include <machine/trap.h>
#include <vm/vm_kmem.h>

/*
 * Mask used to check that local APICS are internal.
 */
#define LAPIC_VERSION_MASK 0x10

/*
 * Common bits for registers in the local vector table.
 */
#define LAPIC_LVT_DELIVERY_FIXED    0x00000000
#define LAPIC_LVT_DELIVERY_NMI      0x00000400
#define LAPIC_LVT_DELIVERY_EXTINT   0x00000700
#define LAPIC_LVT_MASK_INTR         0x00010000

/*
 * LVT timer register bits.
 */
#define LAPIC_LVT_TIMER_PERIODIC    0x00020000

/*
 * Various values related to the local APIC timer.
 */
#define LAPIC_TIMER_DCR_DIV1    0x0000000b
#define LAPIC_TIMER_COUNT_MAX   0xffffffff

/*
 * Delay used to calibrate the local APIC timer, in microseconds.
 */
#define LAPIC_TIMER_CAL_DELAY   100000

/*
 * Spurious-interrupt vector register bits.
 */
#define LAPIC_SVR_SOFT_EN 0x00000100

/*
 * Interrupt command register (lower word) bits.
 */
#define LAPIC_ICR_VECTOR_MASK           0x000000ff
#define LAPIC_ICR_DELIVERY_INIT         0x00000500
#define LAPIC_ICR_DELIVERY_STARTUP      0x00000600
#define LAPIC_ICR_STATUS_PENDING        0x00001000
#define LAPIC_ICR_LEVEL_ASSERT          0x00004000
#define LAPIC_ICR_TRIGGER_LEVEL         0x00008000
#define LAPIC_ICR_DEST_SELF             0x00040000
#define LAPIC_ICR_DEST_ALL_WITH_SELF    0x00080000
#define LAPIC_ICR_DEST_ALL_EXCEPT_SELF  0x000c0000
#define LAPIC_ICR_DEST_MASK             0x000c0000
#define LAPIC_ICR_RESERVED              0xfff32000

/*
 * ICR destination shift and mask.
 */
#define LAPIC_DEST_SHIFT    24
#define LAPIC_DEST_MASK     0xff000000

/*
 * Local APIC registers are accessed with 32-bits loads/stores aligned on
 * 128 bits.
 */
struct lapic_register {
    uint32_t reg;
    uint32_t reserved0;
    uint32_t reserved1;
    uint32_t reserved2;
} __packed;

/*
 * Local APIC register map.
 */
struct lapic_map {
    const struct lapic_register reserved0;
    const struct lapic_register reserved1;

    /*
     * Some processors don't allow writing to this register, and the
     * specification explicitely discourages modifications. Consider it
     * read only.
     */
    const struct lapic_register id;
    const struct lapic_register version;
    const struct lapic_register reserved2;
    const struct lapic_register reserved3;
    const struct lapic_register reserved4;
    const struct lapic_register reserved5;
    struct lapic_register tpr;
    const struct lapic_register reserved6; /* APR */
    const struct lapic_register ppr;
    struct lapic_register eoi;
    const struct lapic_register reserved7; /* RRD */
    struct lapic_register ldr;
    struct lapic_register dfr;
    struct lapic_register svr;
    const struct lapic_register isr0;
    const struct lapic_register isr1;
    const struct lapic_register isr2;
    const struct lapic_register isr3;
    const struct lapic_register isr4;
    const struct lapic_register isr5;
    const struct lapic_register isr6;
    const struct lapic_register isr7;
    const struct lapic_register tmr0;
    const struct lapic_register tmr1;
    const struct lapic_register tmr2;
    const struct lapic_register tmr3;
    const struct lapic_register tmr4;
    const struct lapic_register tmr5;
    const struct lapic_register tmr6;
    const struct lapic_register tmr7;
    const struct lapic_register irr0;
    const struct lapic_register irr1;
    const struct lapic_register irr2;
    const struct lapic_register irr3;
    const struct lapic_register irr4;
    const struct lapic_register irr5;
    const struct lapic_register irr6;
    const struct lapic_register irr7;
    struct lapic_register esr;
    const struct lapic_register reserved8;
    const struct lapic_register reserved9;
    const struct lapic_register reserved10;
    const struct lapic_register reserved11;
    const struct lapic_register reserved12;
    const struct lapic_register reserved13;
    struct lapic_register lvt_cmci;
    struct lapic_register icr_low;
    struct lapic_register icr_high;
    struct lapic_register lvt_timer;
    const struct lapic_register reserved14; /* Thermal sensor register */
    const struct lapic_register reserved15; /* Performance counters register */
    struct lapic_register lvt_lint0;
    struct lapic_register lvt_lint1;
    struct lapic_register lvt_error;
    struct lapic_register timer_icr;
    const struct lapic_register timer_ccr;
    const struct lapic_register reserved16;
    const struct lapic_register reserved17;
    const struct lapic_register reserved18;
    const struct lapic_register reserved19;
    struct lapic_register timer_dcr;
    const struct lapic_register reserved20;
} __packed;

/*
 * Address where local APIC registers are mapped.
 */
static volatile struct lapic_map *lapic_map __read_mostly;

/*
 * Base frequency of the local APIC timer.
 */
static uint32_t lapic_bus_freq __read_mostly;

static bool lapic_initialized __initdata;
static bool lapic_is_unused __initdata;

static uint32_t
lapic_read(const volatile struct lapic_register *r)
{
    return r->reg;
}

static void
lapic_write(volatile struct lapic_register *r, uint32_t value)
{
    r->reg = value;
}

static void __init
lapic_setup_timer(void)
{
    uint32_t c1, c2;

    lapic_write(&lapic_map->timer_dcr, LAPIC_TIMER_DCR_DIV1);

    /* The APIC timer counter should never wrap around here */
    lapic_write(&lapic_map->timer_icr, LAPIC_TIMER_COUNT_MAX);
    c1 = lapic_read(&lapic_map->timer_ccr);
    cpu_delay(LAPIC_TIMER_CAL_DELAY);
    c2 = lapic_read(&lapic_map->timer_ccr);
    lapic_bus_freq = (c1 - c2) * (1000000 / LAPIC_TIMER_CAL_DELAY);
    printf("lapic: bus frequency: %u.%02u MHz\n", lapic_bus_freq / 1000000,
           lapic_bus_freq % 1000000);
    lapic_write(&lapic_map->timer_icr, lapic_bus_freq / HZ);
}

void
lapic_eoi(void)
{
    lapic_write(&lapic_map->eoi, 0);
}

static void __init
lapic_setup_registers(void)
{
    /*
     * LVT mask bits can only be cleared when the local APIC is enabled.
     */
    lapic_write(&lapic_map->svr, LAPIC_SVR_SOFT_EN | TRAP_LAPIC_SPURIOUS);
    lapic_write(&lapic_map->tpr, 0);
    lapic_write(&lapic_map->eoi, 0);
    lapic_write(&lapic_map->esr, 0);
    lapic_write(&lapic_map->lvt_timer, LAPIC_LVT_TIMER_PERIODIC
                                       | TRAP_LAPIC_TIMER);
    lapic_write(&lapic_map->lvt_lint0, LAPIC_LVT_MASK_INTR);
    lapic_write(&lapic_map->lvt_lint1, LAPIC_LVT_MASK_INTR);
    lapic_write(&lapic_map->lvt_error, TRAP_LAPIC_ERROR);
    lapic_write(&lapic_map->timer_dcr, LAPIC_TIMER_DCR_DIV1);
    lapic_write(&lapic_map->timer_icr, lapic_bus_freq / HZ);
}

bool __init
lapic_unused(void)
{
    assert(lapic_initialized);
    return lapic_is_unused;
}

void __init
lapic_setup_unused(void)
{
    lapic_initialized = true;
    lapic_is_unused = true;
}

void __init
lapic_setup(uint32_t map_addr)
{
    uint32_t value;

    lapic_map = vm_kmem_map_pa(map_addr, sizeof(*lapic_map), NULL, NULL);

    if (lapic_map == NULL) {
        panic("lapic: unable to map registers in kernel map");
    }

    value = lapic_read(&lapic_map->version);

    if ((value & LAPIC_VERSION_MASK) != LAPIC_VERSION_MASK) {
        panic("lapic: external local APIC not supported");
    }

    lapic_setup_registers();
    lapic_setup_timer();

    lapic_initialized = true;
}

void __init
lapic_ap_setup(void)
{
    lapic_setup_registers();
}

static void
lapic_ipi(uint32_t apic_id, uint32_t icr)
{
    if ((icr & LAPIC_ICR_DEST_MASK) == 0) {
        lapic_write(&lapic_map->icr_high, apic_id << LAPIC_DEST_SHIFT);
    }

    lapic_write(&lapic_map->icr_low, icr & ~LAPIC_ICR_RESERVED);
}

static void
lapic_ipi_wait(void)
{
    uint32_t value;

    do {
        value = lapic_read(&lapic_map->icr_low);
        cpu_pause();
    } while (value & LAPIC_ICR_STATUS_PENDING);
}

void
lapic_ipi_init_assert(uint32_t apic_id)
{
    lapic_ipi(apic_id, LAPIC_ICR_TRIGGER_LEVEL | LAPIC_ICR_LEVEL_ASSERT
                       | LAPIC_ICR_DELIVERY_INIT);
    lapic_ipi_wait();
}

void
lapic_ipi_init_deassert(uint32_t apic_id)
{
    lapic_ipi(apic_id, LAPIC_ICR_TRIGGER_LEVEL | LAPIC_ICR_DELIVERY_INIT);
    lapic_ipi_wait();
}

void
lapic_ipi_startup(uint32_t apic_id, uint32_t vector)
{
    lapic_ipi(apic_id, LAPIC_ICR_DELIVERY_STARTUP
                       | (vector & LAPIC_ICR_VECTOR_MASK));
    lapic_ipi_wait();
}

void
lapic_ipi_send(uint32_t apic_id, uint32_t vector)
{
    lapic_ipi_wait();
    lapic_ipi(apic_id, vector & LAPIC_ICR_VECTOR_MASK);
}

void
lapic_ipi_broadcast(uint32_t vector)
{
    lapic_ipi_wait();
    lapic_ipi(0, LAPIC_ICR_DEST_ALL_EXCEPT_SELF
                 | (vector & LAPIC_ICR_VECTOR_MASK));
}

void
lapic_timer_intr(struct trap_frame *frame)
{
    (void)frame;

    lapic_eoi();
    thread_tick_intr();
}

void
lapic_error_intr(struct trap_frame *frame)
{
    uint32_t esr;

    (void)frame;
    esr = lapic_read(&lapic_map->esr);
    printf("lapic: error on cpu%u: esr:%08x\n", cpu_id(), esr);
    lapic_write(&lapic_map->esr, 0);
    lapic_eoi();
}

void
lapic_spurious_intr(struct trap_frame *frame)
{
    (void)frame;
    printf("lapic: warning: spurious interrupt\n");

    /* No EOI for this interrupt */
}
