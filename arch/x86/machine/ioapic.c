/*
 * Copyright (c) 2017 Richard Braun.
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
#include <stdint.h>
#include <stdio.h>

#include <kern/assert.h>
#include <kern/error.h>
#include <kern/init.h>
#include <kern/intr.h>
#include <kern/kmem.h>
#include <kern/panic.h>
#include <kern/spinlock.h>
#include <machine/cpu.h>
#include <machine/ioapic.h>
#include <machine/lapic.h>
#include <machine/trap.h>
#include <vm/vm_kmem.h>

#define IOAPIC_REG_VERSION              0x01
#define IOAPIC_REG_IOREDTBL             0x10

#define IOAPIC_VERSION_VERSION_MASK     0x000000ff
#define IOAPIC_VERSION_VERSION_SHIFT    0
#define IOAPIC_VERSION_MAXREDIR_MASK    0x00ff0000
#define IOAPIC_VERSION_MAXREDIR_SHIFT   16

#define IOAPIC_ENTLOW_INTRMASK          0x10000

#define IOAPIC_MAX_ENTRIES 24

struct ioapic_map {
    uint8_t regsel;
    uint8_t _reserved0;
    uint8_t _reserved1;
    uint8_t _reserved2;
    uint32_t _reserved3;
    uint32_t _reserved4;
    uint32_t _reserved5;
    uint32_t win;
};

struct ioapic {
    struct spinlock lock;
    unsigned int id;
    unsigned int apic_id;
    unsigned int version;
    volatile struct ioapic_map *map;
    unsigned int first_intr;
    unsigned int last_intr;
};

static unsigned int ioapic_nr_devs;

static uint32_t
ioapic_read(struct ioapic *ioapic, uint8_t reg)
{
    ioapic->map->regsel = reg;
    return ioapic->map->win;
}

static void
ioapic_write(struct ioapic *ioapic, uint8_t reg, uint32_t value)
{
    ioapic->map->regsel = reg;
    ioapic->map->win = value;
}

static void
ioapic_write_entry_low(struct ioapic *ioapic, unsigned int id, uint32_t value)
{
    assert(id < IOAPIC_MAX_ENTRIES);
    ioapic_write(ioapic, IOAPIC_REG_IOREDTBL + (id * 2), value);
}

static void
ioapic_write_entry_high(struct ioapic *ioapic, unsigned int id, uint32_t value)
{
    assert(id < IOAPIC_MAX_ENTRIES);
    ioapic_write(ioapic, IOAPIC_REG_IOREDTBL + (id * 2) + 1, value);
}

static void
ioapic_intr(struct trap_frame *frame)
{
    intr_handle(frame->vector - TRAP_INTR_FIRST);
}

static struct ioapic * __init
ioapic_create(unsigned int apic_id, uintptr_t addr, unsigned int intr_base)
{
    struct ioapic *ioapic;
    unsigned int i, nr_intrs;
    uint32_t value;

    ioapic = kmem_alloc(sizeof(*ioapic));

    if (ioapic == NULL) {
        panic("ioapic: unable to allocate memory for controller");
    }

    spinlock_init(&ioapic->lock);
    ioapic->id = ioapic_nr_devs;
    ioapic->apic_id = apic_id;
    ioapic->first_intr = intr_base;

    ioapic->map = vm_kmem_map_pa(addr, sizeof(*ioapic->map), NULL, NULL);

    if (ioapic->map == NULL) {
        panic("ioapic: unable to map register window in kernel map");
    }

    value = ioapic_read(ioapic, IOAPIC_REG_VERSION);
    ioapic->version = (value & IOAPIC_VERSION_VERSION_MASK)
                      >> IOAPIC_VERSION_VERSION_SHIFT;
    nr_intrs = ((value & IOAPIC_VERSION_MAXREDIR_MASK)
                >> IOAPIC_VERSION_MAXREDIR_SHIFT) + 1;
    ioapic->last_intr = ioapic->first_intr + nr_intrs - 1;

    if (ioapic->last_intr > (TRAP_INTR_LAST - TRAP_INTR_FIRST)) {
        panic("ioapic: invalid interrupt range");
    }

    for (i = ioapic->first_intr; i < ioapic->last_intr; i++) {
        trap_register(TRAP_INTR_FIRST + i, ioapic_intr);
    }

    printf("ioapic%u: version:%#x intrs:%u-%u\n", ioapic->id,
           ioapic->version, ioapic->first_intr, ioapic->last_intr);

    ioapic_nr_devs++;
    return ioapic;
}

static bool
ioapic_has_intr(const struct ioapic *ioapic, unsigned int intr)
{
    return ((intr >= ioapic->first_intr) && (intr <= ioapic->last_intr));
}

static unsigned int
ioapic_compute_id(const struct ioapic *ioapic, unsigned int intr)
{
    assert(ioapic_has_intr(ioapic, intr));
    return intr - ioapic->first_intr;
}

static void
ioapic_enable(void *priv, unsigned int intr, unsigned int cpu)
{
    struct ioapic *ioapic;
    unsigned long flags;
    unsigned int id;

    ioapic = priv;
    id = ioapic_compute_id(ioapic, intr);

    spinlock_lock_intr_save(&ioapic->lock, &flags);
    ioapic_write_entry_high(ioapic, id, cpu_apic_id(cpu) << 24);
    ioapic_write_entry_low(ioapic, id, TRAP_INTR_FIRST + intr);
    spinlock_unlock_intr_restore(&ioapic->lock, flags);
}

static void
ioapic_disable(void *priv, unsigned int intr)
{
    struct ioapic *ioapic;
    unsigned long flags;
    unsigned int id;

    ioapic = priv;
    id = ioapic_compute_id(ioapic, intr);

    spinlock_lock_intr_save(&ioapic->lock, &flags);
    ioapic_write_entry_low(ioapic, id, IOAPIC_ENTLOW_INTRMASK);
    spinlock_unlock_intr_restore(&ioapic->lock, flags);
}

static void
ioapic_eoi(void *priv, unsigned int intr)
{
    (void)priv;
    (void)intr;

    lapic_eoi();
}

static const struct intr_ops ioapic_ops = {
    .enable = ioapic_enable,
    .disable = ioapic_disable,
    .eoi = ioapic_eoi,
};

void __init
ioapic_register(unsigned int apic_id, uintptr_t addr, unsigned int intr_base)
{
    struct ioapic *ioapic;

    ioapic = ioapic_create(apic_id, addr, intr_base);
    intr_register_ctl(&ioapic_ops, ioapic,
                      ioapic->first_intr, ioapic->last_intr);
}

