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

#include <kern/init.h>
#include <kern/kmem.h>
#include <kern/panic.h>
#include <kern/printk.h>
#include <kern/types.h>
#include <lib/assert.h>
#include <lib/macros.h>
#include <lib/stddef.h>
#include <lib/stdint.h>
#include <lib/string.h>
#include <machine/biosmem.h>
#include <machine/cpu.h>
#include <machine/io.h>
#include <machine/lapic.h>
#include <machine/mps.h>
#include <vm/vm_kmem.h>

/*
 * Alignment of the FPS.
 */
#define MPS_FPS_ALIGN 16

/*
 * Signature of the floating pointer structure.
 */
#define MPS_FPS_SIG "_MP_"

/*
 * Flag of the feature2 byte indicating the presence of the interrupt mode
 * configuration register (IMCR).
 */
#define MPS_FPS_IMCR_PRESENT 0x80

/*
 * IMCR ports and values.
 */
#define MPS_IMCR_PORT_ADDR  0x22
#define MPS_IMCR_PORT_DATA  0x23
#define MPS_IMCR_SELECT     0x70
#define MPS_IMCR_APIC_MODE  0x01

struct mps_fps {
    uint8_t signature[4];
    uint32_t phys_addr;
    uint8_t length;
    uint8_t spec_rev;
    uint8_t checksum;
    uint8_t conf_type;
    uint8_t feature2;
    uint8_t feature3;
    uint8_t feature4;
    uint8_t feature5;
} __packed;

/*
 * Processor entry flags.
 */
#define MPS_PROC_EN 0x1
#define MPS_PROC_BP 0x2

struct mps_proc {
    uint8_t type;
    uint8_t lapic_id;
    uint8_t lapic_version;
    uint8_t cpu_flags;
    uint32_t cpu_signature;
    uint32_t feature_flags;
    uint32_t reserved1;
    uint32_t reserved2;
} __packed;

struct mps_bus {
    uint8_t type;
    uint8_t bus_id;
    uint8_t bus_type[6];
} __packed;

struct mps_ioapic {
    uint8_t type;
    uint8_t id;
    uint8_t version;
    uint8_t flags;
    uint32_t addr;
} __packed;

struct mps_intr {
    uint8_t type;
    uint8_t intr_type;
    uint16_t intr_flags;
    uint8_t src_bus_id;
    uint8_t src_bus_irq;
    uint8_t dst_apic_id;
    uint8_t dst_apic_intr;
} __packed;

union mps_entry {
    uint8_t type;
    struct mps_proc proc;
    struct mps_bus bus;
    struct mps_ioapic ioapic;
    struct mps_intr intr;
} __packed;

/*
 * Signature of the MPS table.
 */
#define MPS_TABLE_SIG "PCMP"

struct mps_cth {
    uint8_t signature[4];
    uint16_t base_table_length;
    uint8_t spec_rev;
    uint8_t checksum;
    uint8_t oem_id[8];
    uint8_t prod_id[12];
    uint32_t oem_table_ptr;
    uint16_t oem_table_size;
    uint16_t entry_count;
    uint32_t lapic_addr;
    uint16_t ext_table_length;
    uint8_t ext_table_checksum;
    uint8_t reserved;
    union mps_entry entries[0];
} __packed;

struct mps_iter {
    const union mps_entry *entry;
    uint16_t index;
    uint16_t size;
};

#define mps_foreach(table, iter) \
for (mps_iter_init(iter, table); mps_iter_valid(iter); mps_iter_next(iter))

/*
 * MPS table entry type codes.
 */
#define MPS_ENTRY_PROC          0
#define MPS_ENTRY_BUS           1
#define MPS_ENTRY_IOAPIC        2
#define MPS_ENTRY_IOINTR        3
#define MPS_ENTRY_LOCAL_INTR    4

/*
 * Array of entry type sizes.
 *
 * The entry type codes must match the indexes of their associated size.
 */
static const size_t mps_entry_sizes[] __initdata = {
    sizeof(struct mps_proc),
    sizeof(struct mps_bus),
    sizeof(struct mps_ioapic),
    sizeof(struct mps_intr),
    sizeof(struct mps_intr)
};

static unsigned int __init
mps_checksum(const void *ptr, size_t size)
{
    const uint8_t *bytes;
    uint8_t checksum;
    size_t i;

    bytes = ptr;
    checksum = 0;

    for (i = 0; i < size; i++)
        checksum += bytes[i];

    return checksum;
}

static int __init
mps_check_fps(const struct mps_fps *fps)
{
    unsigned int checksum;

    if (memcmp(fps->signature, MPS_FPS_SIG, sizeof(fps->signature)) != 0)
        return -1;

    checksum = mps_checksum(fps, sizeof(*fps));

    if (checksum != 0)
        return -1;

    return 0;
}

static int __init
mps_get_fps(vm_phys_t start, size_t size, struct mps_fps *fps)
{
    const struct mps_fps *src;
    unsigned long addr, end, map_addr;
    size_t map_size;
    int error;

    assert(size > 0);
    assert(P2ALIGNED(size, MPS_FPS_ALIGN));

    if (!P2ALIGNED(start, MPS_FPS_ALIGN))
        return -1;

    addr = (unsigned long)vm_kmem_map_pa(start, size, &map_addr, &map_size);

    if (addr == 0)
        panic("mps: unable to map bios memory in kernel map");

    for (end = addr + size; addr < end; addr += MPS_FPS_ALIGN) {
        src = (const struct mps_fps *)addr;
        error = mps_check_fps(src);

        if (!error)
            break;
    }

    if (!(addr < end)) {
        error = -1;
        goto out;
    }

    memcpy(fps, src, sizeof(*fps));
    error = 0;

out:
    vm_kmem_unmap_pa(map_addr, map_size);
    return error;
}

static int __init
mps_find_fps(struct mps_fps *fps)
{
    const uint16_t *ptr;
    unsigned long base, map_addr;
    size_t map_size;
    int error;

    ptr = vm_kmem_map_pa(BIOSMEM_EBDA_PTR, sizeof(*ptr), &map_addr, &map_size);

    if (ptr == NULL)
        panic("mps: unable to map ebda pointer in kernel map");

    base = *((const volatile uint16_t *)ptr);
    vm_kmem_unmap_pa(map_addr, map_size);

    if (base != 0)
        base <<= 4;
    else
        base = BIOSMEM_BASE_END - 1024;

    error = mps_get_fps(base, 1024, fps);

    if (!error)
        return 0;

    error = mps_get_fps(BIOSMEM_ROM, BIOSMEM_END - BIOSMEM_ROM, fps);

    if (!error)
        return 0;

    printk("mps: unable to find floating pointer structure\n");
    return -1;
}

static struct mps_cth * __init
mps_copy_table(const struct mps_fps *fps)
{
    const struct mps_cth *table;
    struct mps_cth *copy;
    unsigned long map_addr;
    size_t size, map_size;
    unsigned int checksum;

    if (fps->phys_addr == 0) {
        printk("mps: table doesn't exist");
        return NULL;
    }

    table = vm_kmem_map_pa(fps->phys_addr, sizeof(*table),
                           &map_addr, &map_size);

    if (table == NULL)
        panic("mps: unable to map table header in kernel map");

    size = ((const volatile struct mps_cth *)table)->base_table_length;
    vm_kmem_unmap_pa(map_addr, map_size);

    table = vm_kmem_map_pa(fps->phys_addr, size, &map_addr, &map_size);

    if (table == NULL)
        panic("mps: unable to map table in kernel map");

    if (memcmp(table->signature, MPS_TABLE_SIG, sizeof(table->signature))
        != 0) {
        printk("mps: invalid table signature\n");
        copy = NULL;
        goto error;
    }

    checksum = mps_checksum(table, size);

    if (checksum != 0) {
        printk("mps: table checksum failed\n");
        copy = NULL;
        goto error;
    }

    copy = kmem_alloc(size);

    if (copy == NULL)
        panic("mps: unable to allocate memory for table copy");

    memcpy(copy, table, size);

error:
    vm_kmem_unmap_pa(map_addr, map_size);
    return copy;
}

static void __init
mps_info(const struct mps_cth *table)
{
    printk("mps: spec revision: 1.%u, %.*s %.*s\n",
           (unsigned int)table->spec_rev,
           (int)sizeof(table->oem_id), table->oem_id,
           (int)sizeof(table->prod_id), table->prod_id);
}

static void __init
mps_set_intr_mode(const struct mps_fps *fps)
{
    uint8_t byte;

    if (!(fps->feature2 & MPS_FPS_IMCR_PRESENT))
        return;

    /* Switch to symmetric I/O mode */
    io_write_byte(MPS_IMCR_PORT_ADDR, MPS_IMCR_SELECT);
    byte = io_read_byte(MPS_IMCR_PORT_DATA);
    byte |= MPS_IMCR_APIC_MODE;
    io_write_byte(MPS_IMCR_PORT_DATA, byte);
}

static void __init
mps_iter_init(struct mps_iter *iter, const struct mps_cth *table)
{
    iter->entry = table->entries;
    iter->index = 0;
    iter->size = table->entry_count;
}

static int __init
mps_iter_valid(const struct mps_iter *iter)
{
    return iter->index < iter->size;
}

static void __init
mps_iter_next(struct mps_iter *iter)
{
    assert(iter->entry->type < ARRAY_SIZE(mps_entry_sizes));
    iter->entry = (void *)iter->entry + mps_entry_sizes[iter->entry->type];
    iter->index++;
}

static void __init
mps_load_proc(const struct mps_proc *proc)
{
    if (!(proc->cpu_flags & MPS_PROC_EN))
        return;

    cpu_mp_register_lapic(proc->lapic_id, proc->cpu_flags & MPS_PROC_BP);
}

static void __init
mps_load_table(const struct mps_cth *table)
{
    struct mps_iter iter;

    lapic_setup(table->lapic_addr);

    mps_foreach(table, &iter) {
        switch (iter.entry->type) {
        case MPS_ENTRY_PROC:
            mps_load_proc(&iter.entry->proc);
            break;
        case MPS_ENTRY_BUS:
        case MPS_ENTRY_IOAPIC:
        case MPS_ENTRY_IOINTR:
        case MPS_ENTRY_LOCAL_INTR:
            break;
        default:
            panic("mps: invalid table entry type");
        }
    }
}

static void __init
mps_free_table(struct mps_cth *table)
{
    kmem_free(table, table->base_table_length);
}

int __init
mps_setup(void)
{
    struct mps_cth *table;
    struct mps_fps fps;
    int error;

    error = mps_find_fps(&fps);

    if (error)
        return error;

    if (fps.conf_type != 0)
        panic("mps: default tables not implemented");
    else {
        table = mps_copy_table(&fps);

        if (table == NULL)
            return -1;
    }

    mps_info(table);
    mps_set_intr_mode(&fps);
    mps_load_table(table);
    mps_free_table(table);
    return 0;
}
