/*
 * Copyright (c) 2012 Richard Braun.
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
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <kern/assert.h>
#include <kern/init.h>
#include <kern/kmem.h>
#include <kern/macros.h>
#include <kern/panic.h>
#include <machine/acpimp.h>
#include <machine/biosmem.h>
#include <machine/cpu.h>
#include <machine/io.h>
#include <machine/lapic.h>
#include <machine/types.h>
#include <vm/vm_kmem.h>

/*
 * Alignment of the RSDP.
 */
#define ACPIMP_RSDP_ALIGN 16

/*
 * Signature of the root system description pointer.
 */
#define ACPIMP_RSDP_SIG "RSD PTR "

struct acpimp_rsdp {
    uint8_t signature[8];
    uint8_t checksum;
    uint8_t oem_id[6];
    uint8_t reserved;
    uint32_t rsdt_address;
} __packed;

/*
 * Size of a buffer which can store a table signature as a string.
 */
#define ACPIMP_SIG_SIZE 5

struct acpimp_sdth {
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

struct acpimp_rsdt {
    struct acpimp_sdth header;
    uint32_t entries[0];
} __packed;

/*
 * MADT entry type codes.
 */
#define ACPIMP_MADT_ENTRY_LAPIC 0

struct acpimp_madt_entry_hdr {
    uint8_t type;
    uint8_t length;
} __packed;

#define ACPIMP_MADT_LAPIC_ENABLED 0x1

struct acpimp_madt_entry_lapic {
    struct acpimp_madt_entry_hdr header;
    uint8_t processor_id;
    uint8_t apic_id;
    uint32_t flags;
} __packed;

union acpimp_madt_entry {
    uint8_t type;
    struct acpimp_madt_entry_hdr header;
    struct acpimp_madt_entry_lapic lapic;
} __packed;

struct acpimp_madt {
    struct acpimp_sdth header;
    uint32_t lapic_addr;
    uint32_t flags;
    union acpimp_madt_entry entries[0];
} __packed;

struct acpimp_madt_iter {
    const union acpimp_madt_entry *entry;
    const union acpimp_madt_entry *end;
};

#define acpimp_madt_foreach(madt, iter) \
for (acpimp_madt_iter_init(iter, madt); \
     acpimp_madt_iter_valid(iter);      \
     acpimp_madt_iter_next(iter))

struct acpimp_table_addr {
    const char *sig;
    struct acpimp_sdth *table;
};

static struct acpimp_table_addr acpimp_table_addrs[] __initdata = {
    { "RSDT",   NULL },
    { "APIC",   NULL }
};

static void __init
acpimp_table_sig(const struct acpimp_sdth *table, char sig[ACPIMP_SIG_SIZE])
{
    memcpy(sig, table->signature, sizeof(table->signature));
    sig[4] = '\0';
}

static int __init
acpimp_table_required(const struct acpimp_sdth *table)
{
    char sig[ACPIMP_SIG_SIZE];
    size_t i;

    acpimp_table_sig(table, sig);

    for (i = 0; i < ARRAY_SIZE(acpimp_table_addrs); i++)
        if (strcmp(sig, acpimp_table_addrs[i].sig) == 0) {
            return 1;
        }

    return 0;
}

static void __init
acpimp_register_table(struct acpimp_sdth *table)
{
    char sig[ACPIMP_SIG_SIZE];
    size_t i;

    acpimp_table_sig(table, sig);

    for (i = 0; i < ARRAY_SIZE(acpimp_table_addrs); i++)
        if (strcmp(sig, acpimp_table_addrs[i].sig) == 0) {
            if (acpimp_table_addrs[i].table != NULL) {
                printf("acpimp: warning: table %s ignored:"
                       " already registered\n", sig);
                return;
            }

            acpimp_table_addrs[i].table = table;
            return;
        }

    printf("acpimp: warning: table '%s' ignored: unknown table\n", sig);
}

static struct acpimp_sdth * __init
acpimp_lookup_table(const char *sig)
{
    size_t i;

    for (i = 0; i < ARRAY_SIZE(acpimp_table_addrs); i++)
        if (strcmp(sig, acpimp_table_addrs[i].sig) == 0) {
            return acpimp_table_addrs[i].table;
        }

    return NULL;
}

static int __init
acpimp_check_tables(void)
{
    size_t i;

    for (i = 0; i < ARRAY_SIZE(acpimp_table_addrs); i++)
        if (acpimp_table_addrs[i].table == NULL) {
            printf("acpimp: error: table %s missing\n",
                   acpimp_table_addrs[i].sig);
            return -1;
        }

    return 0;
}

static void __init
acpimp_free_tables(void)
{
    struct acpimp_sdth *table;
    size_t i;

    for (i = 0; i < ARRAY_SIZE(acpimp_table_addrs); i++) {
        table = acpimp_table_addrs[i].table;

        if (table != NULL) {
            kmem_free(table, table->length);
        }
    }
}

static unsigned int __init
acpimp_checksum(const void *ptr, size_t size)
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
acpimp_check_rsdp(const struct acpimp_rsdp *rsdp)
{
    unsigned int checksum;

    if (memcmp(rsdp->signature, ACPIMP_RSDP_SIG, sizeof(rsdp->signature)) != 0) {
        return -1;
    }

    checksum = acpimp_checksum(rsdp, sizeof(*rsdp));

    if (checksum != 0) {
        return -1;
    }

    return 0;
}

static int __init
acpimp_get_rsdp(phys_addr_t start, size_t size, struct acpimp_rsdp *rsdp)
{
    const struct acpimp_rsdp *src;
    uintptr_t addr, end, map_addr;
    size_t map_size;
    int error;

    assert(size > 0);
    assert(P2ALIGNED(size, ACPIMP_RSDP_ALIGN));

    if (!P2ALIGNED(start, ACPIMP_RSDP_ALIGN)) {
        return -1;
    }

    addr = (uintptr_t)vm_kmem_map_pa(start, size, &map_addr, &map_size);

    if (addr == 0) {
        panic("acpimp: unable to map bios memory in kernel map");
    }

    for (end = addr + size; addr < end; addr += ACPIMP_RSDP_ALIGN) {
        src = (const struct acpimp_rsdp *)addr;
        error = acpimp_check_rsdp(src);

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
acpimp_find_rsdp(struct acpimp_rsdp *rsdp)
{
    const uint16_t *ptr;
    uintptr_t base, map_addr;
    size_t map_size;
    int error;

    ptr = vm_kmem_map_pa(BIOSMEM_EBDA_PTR, sizeof(*ptr), &map_addr, &map_size);

    if (ptr == NULL) {
        panic("acpimp: unable to map ebda pointer in kernel map");
    }

    base = *((const volatile uint16_t *)ptr);
    vm_kmem_unmap_pa(map_addr, map_size);

    if (base != 0) {
        base <<= 4;
        error = acpimp_get_rsdp(base, 1024, rsdp);

        if (!error) {
            return 0;
        }
    }

    error = acpimp_get_rsdp(BIOSMEM_EXT_ROM, BIOSMEM_END - BIOSMEM_EXT_ROM,
                            rsdp);

    if (!error) {
        return 0;
    }

    printf("acpimp: unable to find root system description pointer\n");
    return -1;
}

static void __init
acpimp_info(void)
{
    const struct acpimp_sdth *rsdt;

    rsdt = acpimp_lookup_table("RSDT");
    assert(rsdt != NULL);
    printf("acpimp: revision: %u, oem: %.*s\n", rsdt->revision,
           (int)sizeof(rsdt->oem_id), rsdt->oem_id);
}

static struct acpimp_sdth * __init
acpimp_copy_table(uint32_t addr)
{
    const struct acpimp_sdth *table;
    struct acpimp_sdth *copy;
    uintptr_t map_addr;
    size_t size, map_size;
    unsigned int checksum;

    table = vm_kmem_map_pa(addr, sizeof(*table), &map_addr, &map_size);

    if (table == NULL) {
        panic("acpimp: unable to map acpi data in kernel map");
    }

    if (!acpimp_table_required(table)) {
        copy = NULL;
        goto out;
    }

    size = ((const volatile struct acpimp_sdth *)table)->length;
    vm_kmem_unmap_pa(map_addr, map_size);

    table = vm_kmem_map_pa(addr, size, &map_addr, &map_size);

    if (table == NULL) {
        panic("acpimp: unable to map acpi data in kernel map");
    }

    checksum = acpimp_checksum(table, size);

    if (checksum != 0) {
        char sig[ACPIMP_SIG_SIZE];

        acpimp_table_sig(table, sig);
        printf("acpimp: table %s: invalid checksum\n", sig);
        copy = NULL;
        goto out;
    }

    copy = kmem_alloc(size);

    if (copy == NULL) {
        panic("acpimp: unable to allocate memory for acpi data copy");
    }

    memcpy(copy, table, size);

out:
    vm_kmem_unmap_pa(map_addr, map_size);
    return copy;
}

static int __init
acpimp_copy_tables(const struct acpimp_rsdp *rsdp)
{
    struct acpimp_rsdt *rsdt;
    struct acpimp_sdth *table;
    uint32_t *addr, *end;
    int error;

    table = acpimp_copy_table(rsdp->rsdt_address);

    if (table == NULL) {
        return -1;
    }

    acpimp_register_table(table);

    rsdt = structof(table, struct acpimp_rsdt, header);
    end = (void *)rsdt + rsdt->header.length;

    for (addr = rsdt->entries; addr < end; addr++) {
        table = acpimp_copy_table(*addr);

        if (table == NULL) {
            continue;
        }

        acpimp_register_table(table);
    }

    error = acpimp_check_tables();

    if (error) {
        goto error;
    }

    return 0;

error:
    acpimp_free_tables();
    return -1;
}

static void __init
acpimp_madt_iter_init(struct acpimp_madt_iter *iter,
                      const struct acpimp_madt *madt)
{
    iter->entry = madt->entries;
    iter->end = (void *)madt + madt->header.length;
}

static int __init
acpimp_madt_iter_valid(const struct acpimp_madt_iter *iter)
{
    return iter->entry < iter->end;
}

static void __init
acpimp_madt_iter_next(struct acpimp_madt_iter *iter)
{
    iter->entry = (void *)iter->entry + iter->entry->header.length;
}

static void __init
acpimp_load_lapic(const struct acpimp_madt_entry_lapic *lapic, int *is_bsp)
{
    if (!(lapic->flags & ACPIMP_MADT_LAPIC_ENABLED)) {
        return;
    }

    cpu_mp_register_lapic(lapic->apic_id, *is_bsp);
    *is_bsp = 0;
}

static void __init
acpimp_load_madt(void)
{
    const struct acpimp_sdth *table;
    const struct acpimp_madt *madt;
    struct acpimp_madt_iter iter;
    int is_bsp;

    table = acpimp_lookup_table("APIC");
    assert(table != NULL);
    madt = structof(table, struct acpimp_madt, header);
    lapic_setup(madt->lapic_addr);
    is_bsp = 1;

    acpimp_madt_foreach(madt, &iter) {
        switch (iter.entry->type) {
        case ACPIMP_MADT_ENTRY_LAPIC:
            acpimp_load_lapic(&iter.entry->lapic, &is_bsp);
            break;
        }
    }
}

int __init
acpimp_setup(void)
{
    struct acpimp_rsdp rsdp;
    int error;

    error = acpimp_find_rsdp(&rsdp);

    if (error) {
        return error;
    }

    error = acpimp_copy_tables(&rsdp);

    if (error) {
        return error;
    }

    acpimp_info();
    acpimp_load_madt();
    acpimp_free_tables();
    return 0;
}
