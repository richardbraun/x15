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

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>

#include <kern/error.h>
#include <kern/init.h>
#include <kern/intr.h>
#include <kern/kmem.h>
#include <kern/log.h>
#include <kern/macros.h>
#include <kern/panic.h>
#include <kern/spinlock.h>
#include <machine/cpu.h>
#include <machine/ioapic.h>
#include <machine/lapic.h>
#include <machine/pic.h>
#include <machine/trap.h>
#include <vm/vm_kmem.h>

#define IOAPIC_REG_VERSION              0x01
#define IOAPIC_REG_IOREDTBL             0x10

#define IOAPIC_VERSION_VERSION_MASK     0x000000ff
#define IOAPIC_VERSION_VERSION_SHIFT    0
#define IOAPIC_VERSION_MAXREDIR_MASK    0x00ff0000
#define IOAPIC_VERSION_MAXREDIR_SHIFT   16

#define IOAPIC_ENTLOW_FIXED_DEST        0x00000
#define IOAPIC_ENTLOW_PHYS_DELIVERY     0x00000
#define IOAPIC_ENTLOW_ACTIVE_LOW        0x02000
#define IOAPIC_ENTLOW_LEVEL             0x08000
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

/*
 * Interrupt source override descriptor.
 */
struct ioapic_iso {
    uint32_t gsi;
    uint8_t source;
    bool active_high;
    bool edge_triggered;
};

struct ioapic {
    struct spinlock lock;
    unsigned int id;
    unsigned int apic_id;
    unsigned int version;
    volatile struct ioapic_map *map;
    unsigned int first_gsi;
    unsigned int last_gsi;
};

static unsigned int ioapic_nr_devs;

static struct ioapic_iso ioapic_isos[PIC_MAX_INTR + 1];
static unsigned int ioapic_nr_isos;

static void
ioapic_iso_init(struct ioapic_iso *iso, uint8_t source, uint32_t gsi,
                bool active_high, bool edge_triggered)
{
    iso->source = source;
    iso->gsi = gsi;
    iso->active_high = active_high;
    iso->edge_triggered = edge_triggered;
}

static struct ioapic_iso * __init
ioapic_alloc_iso(void)
{
    struct ioapic_iso *iso;

    if (ioapic_nr_isos >= ARRAY_SIZE(ioapic_isos)) {
        log_err("ioapic: too many interrupt overrides");
        return NULL;
    }

    iso = &ioapic_isos[ioapic_nr_isos];
    ioapic_nr_isos++;
    return iso;
}

static struct ioapic_iso *
ioapic_lookup_iso(unsigned int intr)
{
    struct ioapic_iso *iso;
    unsigned int i;

    for (i = 0; i < ioapic_nr_isos; i++) {
        iso = &ioapic_isos[i];

        if (intr == iso->source) {
            return iso;
        }
    }

    return NULL;
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

static void
ioapic_intr(struct trap_frame *frame)
{
    intr_handle(frame->vector - TRAP_INTR_FIRST);
}

static struct ioapic * __init
ioapic_create(unsigned int apic_id, uintptr_t addr, unsigned int gsi_base)
{
    struct ioapic *ioapic;
    unsigned int i, nr_gsis;
    uint32_t value;

    ioapic = kmem_alloc(sizeof(*ioapic));

    if (ioapic == NULL) {
        panic("ioapic: unable to allocate memory for controller");
    }

    spinlock_init(&ioapic->lock);
    ioapic->id = ioapic_nr_devs;
    ioapic->apic_id = apic_id;
    ioapic->first_gsi = gsi_base;

    ioapic->map = vm_kmem_map_pa(addr, sizeof(*ioapic->map), NULL, NULL);

    if (ioapic->map == NULL) {
        panic("ioapic: unable to map register window in kernel map");
    }

    value = ioapic_read(ioapic, IOAPIC_REG_VERSION);
    ioapic->version = (value & IOAPIC_VERSION_VERSION_MASK)
                      >> IOAPIC_VERSION_VERSION_SHIFT;
    nr_gsis = ((value & IOAPIC_VERSION_MAXREDIR_MASK)
               >> IOAPIC_VERSION_MAXREDIR_SHIFT) + 1;
    ioapic->last_gsi = ioapic->first_gsi + nr_gsis - 1;

    /* XXX This assumes that interrupts are mapped 1:1 to traps */
    if (ioapic->last_gsi > (TRAP_INTR_LAST - TRAP_INTR_FIRST)) {
        panic("ioapic: invalid interrupt range");
    }

    for (i = ioapic->first_gsi; i < ioapic->last_gsi; i++) {
        trap_register(TRAP_INTR_FIRST + i, ioapic_intr);
    }

    log_info("ioapic%u: version:%#x gsis:%u-%u", ioapic->id,
             ioapic->version, ioapic->first_gsi, ioapic->last_gsi);

    ioapic_nr_devs++;
    return ioapic;
}

__unused static bool
ioapic_has_gsi(const struct ioapic *ioapic, unsigned int gsi)
{
    return ((gsi >= ioapic->first_gsi) && (gsi <= ioapic->last_gsi));
}

static unsigned int
ioapic_compute_id(const struct ioapic *ioapic, unsigned int gsi)
{
    assert(ioapic_has_gsi(ioapic, gsi));
    return gsi - ioapic->first_gsi;
}

static void
ioapic_compute_entry(uint32_t *highp, uint32_t *lowp,
                     unsigned int apic_id, unsigned int intr,
                     bool active_high, bool edge_triggered)
{
    assert(apic_id < 16);
    assert(intr < (TRAP_NR_VECTORS - TRAP_INTR_FIRST));

    *highp = apic_id << 24;
    *lowp = (!edge_triggered ? IOAPIC_ENTLOW_LEVEL : 0)
            | (!active_high ? IOAPIC_ENTLOW_ACTIVE_LOW : 0)
            | IOAPIC_ENTLOW_PHYS_DELIVERY
            | IOAPIC_ENTLOW_FIXED_DEST
            | (TRAP_INTR_FIRST + intr);
}

static void
ioapic_enable(void *priv, unsigned int intr, unsigned int cpu)
{
    bool active_high, edge_triggered;
    const struct ioapic_iso *iso;
    uint32_t high, low, gsi;
    struct ioapic *ioapic;
    unsigned long flags;
    unsigned int id;

    iso = ioapic_lookup_iso(intr);

    /* XXX These are defaults that should work with architectural devices */
    if (iso == NULL) {
        active_high = true;
        edge_triggered = true;
        gsi = intr;
    } else {
        active_high = iso->active_high;
        edge_triggered = iso->edge_triggered;
        gsi = iso->gsi;
    }

    ioapic = priv;
    id = ioapic_compute_id(ioapic, gsi);
    ioapic_compute_entry(&high, &low, cpu_apic_id(cpu), intr,
                         active_high, edge_triggered);

    spinlock_lock_intr_save(&ioapic->lock, &flags);
    ioapic_write_entry_high(ioapic, id, high);
    ioapic_write_entry_low(ioapic, id, low);
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
ioapic_setup(void)
{
    ioapic_nr_devs = 0;
    ioapic_nr_isos = 0;
}

void __init
ioapic_register(unsigned int apic_id, uintptr_t addr, unsigned int gsi_base)
{
    struct ioapic *ioapic;

    ioapic = ioapic_create(apic_id, addr, gsi_base);

    /*
     * XXX This assumes that any interrupt override source is included
     * in the GSI range.
     */
    intr_register_ctl(&ioapic_ops, ioapic, ioapic->first_gsi, ioapic->last_gsi);
}

void __init
ioapic_override(uint8_t source, uint32_t gsi,
                bool active_high, bool edge_triggered)
{
    struct ioapic_iso *iso;

    iso = ioapic_alloc_iso();

    if (iso == NULL) {
        return;
    }

    ioapic_iso_init(iso, source, gsi, active_high, edge_triggered);
}
