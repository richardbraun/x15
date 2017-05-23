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
    unsigned int id;
    unsigned int version;
    volatile struct ioapic_map *map;
    unsigned int first_intr;
    unsigned int last_intr;
};

static struct ioapic *ioapic_devs;
static unsigned int ioapic_nr_devs;

/*
 * Global lock.
 *
 * Interrupts must be disabled when holding this lock.
 */
static struct spinlock ioapic_lock;

static struct ioapic *
ioapic_get(unsigned int id)
{
    assert(id < ioapic_nr_devs);
    return &ioapic_devs[id];
}

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
ioapic_enable_intr(struct ioapic *ioapic, unsigned int intr,
                   unsigned int cpu, unsigned int vector)
{
    unsigned int id;

    id = ioapic_compute_id(ioapic, intr);
    ioapic_write_entry_high(ioapic, id, cpu_apic_id(cpu) << 24);
    ioapic_write_entry_low(ioapic, id, vector);
}

static void
ioapic_disable_intr(struct ioapic *ioapic, unsigned int intr)
{
    unsigned int id;

    id = ioapic_compute_id(ioapic, intr);
    ioapic_write_entry_low(ioapic, id, IOAPIC_ENTLOW_INTRMASK);
}

static void
ioapic_intr(struct trap_frame *frame)
{
    lapic_eoi();
    printf("ioapic: cpu:%u vector:%lu\n", cpu_id(), frame->vector);
}

void __init
ioapic_setup(void)
{
    ioapic_devs = NULL;
    ioapic_nr_devs = 0;
    spinlock_init(&ioapic_lock);
}

static void __init
ioapic_init(struct ioapic *ioapic, unsigned int id,
            uintptr_t addr, unsigned int intr_base)
{
    unsigned int i, nr_intrs;
    uint32_t value;

    ioapic->id = id;
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

    printf("ioapic%u: version:%#x intrs:%u-%u\n", ioapic->id,
           ioapic->version, ioapic->first_intr, ioapic->last_intr);

    for (i = ioapic->first_intr; i < ioapic->last_intr; i++) {
        trap_register(TRAP_INTR_FIRST + i, ioapic_intr);
    }
}

void __init
ioapic_register(unsigned int id, uintptr_t addr, unsigned int intr_base)
{
    struct ioapic *tmp;

    spinlock_lock(&ioapic_lock);

    tmp = kmem_alloc((ioapic_nr_devs + 1) * sizeof(*ioapic_devs));

    if (tmp == NULL) {
        panic("ioapic: unable to allocate memory for device");
    }

    memcpy(tmp, ioapic_devs, ioapic_nr_devs);
    kmem_free(ioapic_devs, ioapic_nr_devs * sizeof(*ioapic_devs));
    ioapic_devs = tmp;
    ioapic_nr_devs++;

    ioapic_init(ioapic_get(ioapic_nr_devs - 1), id, addr, intr_base);

    spinlock_unlock(&ioapic_lock);
}

static struct ioapic *
ioapic_lookup(unsigned int intr)
{
    struct ioapic *ioapic;
    unsigned int i;

    for (i = 0; i < ioapic_nr_devs; i++) {
        ioapic = &ioapic_devs[i];

        if ((intr >= ioapic->first_intr) && (intr <= ioapic->last_intr)) {
            return ioapic;
        }
    }

    return NULL;
}

int
ioapic_enable(unsigned int intr, unsigned int cpu, unsigned int vector)
{
    struct ioapic *ioapic;
    unsigned long flags;
    int error;

    spinlock_lock_intr_save(&ioapic_lock, &flags);

    ioapic = ioapic_lookup(intr);

    if (ioapic == NULL) {
        error = ERROR_NODEV;
        goto out;
    }

    ioapic_enable_intr(ioapic, intr, cpu, vector);
    error = 0;

out:
    spinlock_unlock_intr_restore(&ioapic_lock, flags);
    return error;
}

void
ioapic_disable(unsigned int intr)
{
    unsigned long flags;

    spinlock_lock_intr_save(&ioapic_lock, &flags);
    ioapic_disable_intr(ioapic_lookup(intr), intr);
    spinlock_unlock_intr_restore(&ioapic_lock, flags);
}
