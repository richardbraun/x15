/*
 * Copyright (c) 2012-2017 Richard Braun.
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
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <kern/init.h>
#include <kern/intr.h>
#include <kern/kmem.h>
#include <kern/log.h>
#include <kern/macros.h>
#include <kern/panic.h>
#include <kern/percpu.h>
#include <kern/shutdown.h>
#include <machine/acpi.h>
#include <machine/biosmem.h>
#include <machine/cpu.h>
#include <machine/io.h>
#include <machine/ioapic.h>
#include <machine/lapic.h>
#include <machine/pic.h>
#include <machine/pit.h>
#include <machine/types.h>
#include <vm/vm_kmem.h>

/*
 * Priority of the shutdown operations.
 *
 * Higher than all other methods.
 */
#define ACPI_SHUTDOWN_PRIORITY 10

#define ACPI_GAS_ASID_SYSIO 1

struct acpi_gas {
    uint8_t asid;
    uint8_t reg_width;
    uint8_t reg_offset;
    uint8_t access_size;
    uint64_t addr;
} __packed;

#define ACPI_RSDP_ALIGN 16

#define ACPI_RSDP_SIG "RSD PTR "

struct acpi_rsdp {
    uint8_t signature[8];
    uint8_t checksum;
    uint8_t oem_id[6];
    uint8_t reserved;
    uint32_t rsdt_address;
} __packed;

#define ACPI_SIG_SIZE 5

struct acpi_sdth {
    uint8_t signature[4];
    uint32_t length;
    uint8_t revision;
    uint8_t checksum;
    uint8_t oem_id[6];
    uint8_t oem_table_id[8];
    uint32_t oem_revision;
    uint8_t creator_id[4];
    uint32_t creator_revision;
} __packed;

struct acpi_rsdt {
    struct acpi_sdth header;
    uint32_t entries[0];
} __packed;

#define ACPI_MADT_ENTRY_LAPIC     0
#define ACPI_MADT_ENTRY_IOAPIC    1
#define ACPI_MADT_ENTRY_ISO       2

struct acpi_madt_entry_hdr {
    uint8_t type;
    uint8_t length;
} __packed;

#define ACPI_MADT_LAPIC_ENABLED 0x1

struct acpi_madt_entry_lapic {
    struct acpi_madt_entry_hdr header;
    uint8_t processor_id;
    uint8_t apic_id;
    uint32_t flags;
} __packed;

struct acpi_madt_entry_ioapic {
    struct acpi_madt_entry_hdr header;
    uint8_t id;
    uint8_t _reserved;
    uint32_t addr;
    uint32_t base;
} __packed;

#define ACPI_MADT_ISO_POL_DEFAULT   0x00
#define ACPI_MADT_ISO_POL_HIGH      0x01
#define ACPI_MADT_ISO_POL_LOW       0x03
#define ACPI_MADT_ISO_POL_MASK      0x03
#define ACPI_MADT_ISO_TRIG_DEFAULT  0x00
#define ACPI_MADT_ISO_TRIG_EDGE     0x04
#define ACPI_MADT_ISO_TRIG_LEVEL    0x0c
#define ACPI_MADT_ISO_TRIG_MASK     0x0c

struct acpi_madt_entry_iso {
    struct acpi_madt_entry_hdr header;
    uint8_t bus;
    uint8_t source;
    uint32_t gsi;
    int16_t flags;
} __packed;

union acpi_madt_entry {
    uint8_t type;
    struct acpi_madt_entry_hdr header;
    struct acpi_madt_entry_lapic lapic;
    struct acpi_madt_entry_ioapic ioapic;
    struct acpi_madt_entry_iso iso;
} __packed;

#define ACPI_MADT_PC_COMPAT 0x1

struct acpi_madt {
    struct acpi_sdth header;
    uint32_t lapic_addr;
    uint32_t flags;
    union acpi_madt_entry entries[0];
} __packed;

struct acpi_madt_iter {
    const union acpi_madt_entry *entry;
    const union acpi_madt_entry *end;
};

#define acpi_madt_foreach(madt, iter) \
for (acpi_madt_iter_init(iter, madt); \
     acpi_madt_iter_valid(iter);      \
     acpi_madt_iter_next(iter))

#define ACPI_FADT_FL_RESET_REG_SUP  0x400

struct acpi_fadt {
    union {
        struct acpi_sdth header;
        char unused[112];
    };

    uint32_t flags;
    struct acpi_gas reset_reg;
    uint8_t reset_value;
} __packed;

struct acpi_table_addr {
    const char *sig;
    struct acpi_sdth *table;
};

static struct acpi_table_addr acpi_table_addrs[] __initdata = {
    { "RSDT", NULL },
    { "APIC", NULL },
    { "FACP", NULL },
};

static struct acpi_gas acpi_reset_reg;
static uint8_t acpi_reset_value;

static void __init
acpi_table_sig(const struct acpi_sdth *table, char *sig)
{
    memcpy(sig, table->signature, sizeof(table->signature));
    sig[4] = '\0';
}

static int __init
acpi_table_required(const struct acpi_sdth *table)
{
    char sig[ACPI_SIG_SIZE];
    size_t i;

    acpi_table_sig(table, sig);

    for (i = 0; i < ARRAY_SIZE(acpi_table_addrs); i++) {
        if (strcmp(sig, acpi_table_addrs[i].sig) == 0) {
            return 1;
        }
    }

    return 0;
}

static void __init
acpi_register_table(struct acpi_sdth *table)
{
    char sig[ACPI_SIG_SIZE];
    size_t i;

    acpi_table_sig(table, sig);

    for (i = 0; i < ARRAY_SIZE(acpi_table_addrs); i++) {
        if (strcmp(sig, acpi_table_addrs[i].sig) == 0) {
            if (acpi_table_addrs[i].table != NULL) {
                log_warning("acpi: table %s ignored: already registered", sig);
                return;
            }

            acpi_table_addrs[i].table = table;
            return;
        }
    }

    log_warning("acpi: table '%s' ignored: unknown table", sig);
}

static struct acpi_sdth * __init
acpi_lookup_table(const char *sig)
{
    size_t i;

    for (i = 0; i < ARRAY_SIZE(acpi_table_addrs); i++) {
        if (strcmp(sig, acpi_table_addrs[i].sig) == 0) {
            return acpi_table_addrs[i].table;
        }
    }

    return NULL;
}

static int __init
acpi_check_tables(void)
{
    size_t i;

    for (i = 0; i < ARRAY_SIZE(acpi_table_addrs); i++) {
        if (acpi_table_addrs[i].table == NULL) {
            log_err("acpi: table %s missing", acpi_table_addrs[i].sig);
            return -1;
        }
    }

    return 0;
}

static void __init
acpi_free_tables(void)
{
    struct acpi_sdth *table;
    size_t i;

    for (i = 0; i < ARRAY_SIZE(acpi_table_addrs); i++) {
        table = acpi_table_addrs[i].table;

        if (table != NULL) {
            kmem_free(table, table->length);
        }
    }
}

static unsigned int __init
acpi_checksum(const void *ptr, size_t size)
{
    const uint8_t *bytes;
    uint8_t checksum;
    size_t i;

    bytes = ptr;
    checksum = 0;

    for (i = 0; i < size; i++) {
        checksum += bytes[i];
    }

    return checksum;
}

static int __init
acpi_check_rsdp(const struct acpi_rsdp *rsdp)
{
    unsigned int checksum;

    if (memcmp(rsdp->signature, ACPI_RSDP_SIG, sizeof(rsdp->signature)) != 0) {
        return -1;
    }

    checksum = acpi_checksum(rsdp, sizeof(*rsdp));

    if (checksum != 0) {
        return -1;
    }

    return 0;
}

static int __init
acpi_get_rsdp(phys_addr_t start, size_t size, struct acpi_rsdp *rsdp)
{
    const struct acpi_rsdp *src;
    uintptr_t addr, end, map_addr;
    size_t map_size;
    int error;

    assert(size > 0);
    assert(P2ALIGNED(size, ACPI_RSDP_ALIGN));

    if (!P2ALIGNED(start, ACPI_RSDP_ALIGN)) {
        return -1;
    }

    addr = (uintptr_t)vm_kmem_map_pa(start, size, &map_addr, &map_size);

    if (addr == 0) {
        panic("acpi: unable to map bios memory in kernel map");
    }

    for (end = addr + size; addr < end; addr += ACPI_RSDP_ALIGN) {
        src = (const struct acpi_rsdp *)addr;
        error = acpi_check_rsdp(src);

        if (!error) {
            break;
        }
    }

    if (!(addr < end)) {
        error = -1;
        goto out;
    }

    memcpy(rsdp, src, sizeof(*rsdp));
    error = 0;

out:
    vm_kmem_unmap_pa(map_addr, map_size);
    return error;
}

static int __init
acpi_find_rsdp(struct acpi_rsdp *rsdp)
{
    const uint16_t *ptr;
    uintptr_t base, map_addr;
    size_t map_size;
    int error;

    ptr = vm_kmem_map_pa(BIOSMEM_EBDA_PTR, sizeof(*ptr), &map_addr, &map_size);

    if (ptr == NULL) {
        panic("acpi: unable to map ebda pointer in kernel map");
    }

    base = *((const volatile uint16_t *)ptr);
    vm_kmem_unmap_pa(map_addr, map_size);

    if (base != 0) {
        base <<= 4;
        error = acpi_get_rsdp(base, 1024, rsdp);

        if (!error) {
            return 0;
        }
    }

    error = acpi_get_rsdp(BIOSMEM_EXT_ROM, BIOSMEM_END - BIOSMEM_EXT_ROM,
                            rsdp);

    if (!error) {
        return 0;
    }

    log_debug("acpi: unable to find root system description pointer");
    return -1;
}

static void __init
acpi_info(void)
{
    const struct acpi_sdth *rsdt;

    rsdt = acpi_lookup_table("RSDT");
    assert(rsdt != NULL);
    log_debug("acpi: revision: %u, oem: %.*s", rsdt->revision,
              (int)sizeof(rsdt->oem_id), rsdt->oem_id);
}

static struct acpi_sdth * __init
acpi_copy_table(uint32_t addr)
{
    const struct acpi_sdth *table;
    struct acpi_sdth *copy;
    uintptr_t map_addr;
    size_t size, map_size;
    unsigned int checksum;

    table = vm_kmem_map_pa(addr, sizeof(*table), &map_addr, &map_size);

    if (table == NULL) {
        panic("acpi: unable to map acpi data in kernel map");
    }

    if (!acpi_table_required(table)) {
        copy = NULL;
        goto out;
    }

    size = ((const volatile struct acpi_sdth *)table)->length;
    vm_kmem_unmap_pa(map_addr, map_size);

    table = vm_kmem_map_pa(addr, size, &map_addr, &map_size);

    if (table == NULL) {
        panic("acpi: unable to map acpi data in kernel map");
    }

    checksum = acpi_checksum(table, size);

    if (checksum != 0) {
        char sig[ACPI_SIG_SIZE];

        acpi_table_sig(table, sig);
        log_err("acpi: table %s: invalid checksum", sig);
        copy = NULL;
        goto out;
    }

    copy = kmem_alloc(size);

    if (copy == NULL) {
        panic("acpi: unable to allocate memory for acpi data copy");
    }

    memcpy(copy, table, size);

out:
    vm_kmem_unmap_pa(map_addr, map_size);
    return copy;
}

static int __init
acpi_copy_tables(const struct acpi_rsdp *rsdp)
{
    struct acpi_rsdt *rsdt;
    struct acpi_sdth *table;
    uint32_t *addr, *end;
    int error;

    table = acpi_copy_table(rsdp->rsdt_address);

    if (table == NULL) {
        return -1;
    }

    acpi_register_table(table);

    rsdt = structof(table, struct acpi_rsdt, header);
    end = (void *)rsdt + rsdt->header.length;

    for (addr = rsdt->entries; addr < end; addr++) {
        table = acpi_copy_table(*addr);

        if (table == NULL) {
            continue;
        }

        acpi_register_table(table);
    }

    error = acpi_check_tables();

    if (error) {
        goto error;
    }

    return 0;

error:
    acpi_free_tables();
    return -1;
}

static void __init
acpi_madt_iter_init(struct acpi_madt_iter *iter,
                      const struct acpi_madt *madt)
{
    iter->entry = madt->entries;
    iter->end = (void *)madt + madt->header.length;
}

static int __init
acpi_madt_iter_valid(const struct acpi_madt_iter *iter)
{
    return iter->entry < iter->end;
}

static void __init
acpi_madt_iter_next(struct acpi_madt_iter *iter)
{
    iter->entry = (void *)iter->entry + iter->entry->header.length;
}

static void __init
acpi_load_lapic(const struct acpi_madt_entry_lapic *lapic, int *is_bsp)
{
    if (!(lapic->flags & ACPI_MADT_LAPIC_ENABLED)) {
        return;
    }

    cpu_mp_register_lapic(lapic->apic_id, *is_bsp);
    *is_bsp = 0;
}

static void __init
acpi_load_ioapic(const struct acpi_madt_entry_ioapic *ioapic)
{
    ioapic_register(ioapic->id, ioapic->addr, ioapic->base);
}

static void __init
acpi_load_iso(const struct acpi_madt_entry_iso *iso)
{
    bool active_high, edge_triggered;

    if (iso->bus != 0) {
        log_err("acpi: invalid interrupt source override bus");
        return;
    }

    switch (iso->flags & ACPI_MADT_ISO_POL_MASK) {
    case ACPI_MADT_ISO_POL_DEFAULT:
    case ACPI_MADT_ISO_POL_HIGH:
        active_high = true;
        break;
    case ACPI_MADT_ISO_POL_LOW:
        active_high = false;
        break;
    default:
        log_err("acpi: invalid polarity");
        return;
    }

    switch (iso->flags & ACPI_MADT_ISO_TRIG_MASK) {
    case ACPI_MADT_ISO_TRIG_DEFAULT:
    case ACPI_MADT_ISO_TRIG_EDGE:
        edge_triggered = true;
        break;
    case ACPI_MADT_ISO_TRIG_LEVEL:
        edge_triggered = false;
        break;
    default:
        log_err("acpi: invalid trigger mode");
        return;
    }

    ioapic_override(iso->source, iso->gsi, active_high, edge_triggered);
}

static void __init
acpi_load_madt(void)
{
    const struct acpi_sdth *table;
    const struct acpi_madt *madt;
    struct acpi_madt_iter iter;
    int is_bsp;

    table = acpi_lookup_table("APIC");
    assert(table != NULL);
    madt = structof(table, struct acpi_madt, header);

    lapic_setup(madt->lapic_addr);
    is_bsp = 1;

    acpi_madt_foreach(madt, &iter) {
        switch (iter.entry->type) {
        case ACPI_MADT_ENTRY_LAPIC:
            acpi_load_lapic(&iter.entry->lapic, &is_bsp);
            break;
        case ACPI_MADT_ENTRY_IOAPIC:
            acpi_load_ioapic(&iter.entry->ioapic);
            break;
        case ACPI_MADT_ENTRY_ISO:
            acpi_load_iso(&iter.entry->iso);
            break;
        }
    }

    if (madt->flags & ACPI_MADT_PC_COMPAT) {
        pic_setup_disabled();
    }
}

static void
acpi_shutdown_reset_sysio(uint64_t addr)
{
    if (addr > UINT16_MAX) {
        log_warning("acpi: invalid sysio address");
        return;
    }

    io_write_byte((uint16_t)addr, acpi_reset_value);
}

static void
acpi_shutdown_reset(void)
{
    if ((acpi_reset_reg.reg_width != 8) || (acpi_reset_reg.reg_offset != 0)) {
        log_warning("acpi: invalid reset register");
        return;
    }

    switch (acpi_reset_reg.asid) {
    case ACPI_GAS_ASID_SYSIO:
        acpi_shutdown_reset_sysio(acpi_reset_reg.addr);
        break;
    default:
        log_warning("acpi: unsupported reset register type");
    }
}

static struct shutdown_ops acpi_shutdown_ops = {
    .reset = acpi_shutdown_reset,
};

static void __init
acpi_load_fadt(void)
{
    const struct acpi_sdth *table;
    const struct acpi_fadt *fadt;

    table = acpi_lookup_table("FACP");

    if (table == NULL) {
        log_debug("acpi: unable to find FADT table");
        return;
    }

    fadt = structof(table, struct acpi_fadt, header);

    if (!(fadt->flags & ACPI_FADT_FL_RESET_REG_SUP)) {
        log_debug("acpi: reset register not supported");
        return;
    }

    acpi_reset_reg = fadt->reset_reg;
    acpi_reset_value = fadt->reset_value;
    shutdown_register(&acpi_shutdown_ops, ACPI_SHUTDOWN_PRIORITY);
}

static int __init
acpi_setup(void)
{
    struct acpi_rsdp rsdp;
    int error;

    error = acpi_find_rsdp(&rsdp);

    if (error) {
        goto error;
    }

    error = acpi_copy_tables(&rsdp);

    if (error) {
        goto error;
    }

    acpi_info();
    acpi_load_madt();
    acpi_load_fadt();
    acpi_free_tables();

    return 0;

error:
    /*
     * For the sake of simplicity, it has been decided to ignore legacy
     * specifications such as the multiprocessor specification, and use
     * ACPI only. If ACPI is unavailable, consider the APIC system to
     * be missing and fall back to using the legacy XT-PIC and PIT.
     */
    pic_setup();
    pit_setup();
    return 0;
}

INIT_OP_DEFINE(acpi_setup,
               INIT_OP_DEP(cpu_setup, true),
               INIT_OP_DEP(intr_bootstrap, true),
               INIT_OP_DEP(kmem_setup, true),
               INIT_OP_DEP(log_setup, true),
               INIT_OP_DEP(percpu_setup, true),
               INIT_OP_DEP(shutdown_bootstrap, true),
               INIT_OP_DEP(trap_setup, true),
               INIT_OP_DEP(vm_kmem_setup, true));
