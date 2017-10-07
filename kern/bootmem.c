/*
 * Copyright (c) 2010-2017 Richard Braun.
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

#include <kern/bootmem.h>
#include <kern/error.h>
#include <kern/macros.h>
#include <machine/boot.h>
#include <machine/pmem.h>
#include <machine/types.h>
#include <vm/vm_kmem.h>
#include <vm/vm_page.h>

#define BOOTMEM_MAX_RESERVED_RANGES 64

/*
 * Contiguous block of physical memory.
 */
struct bootmem_zone {
    phys_addr_t start;
    phys_addr_t end;
    bool registered;
    bool direct_mapped;
};

/*
 * Physical zone boundaries.
 */
static struct bootmem_zone bootmem_zones[PMEM_MAX_ZONES] __bootdata;

/*
 * Physical memory range descriptor.
 *
 * The start and end addresses must not be page-aligned, since there
 * could be more than one range inside a single page.
 */
struct bootmem_range {
    phys_addr_t start;
    phys_addr_t end;
    bool temporary;
};

/*
 * Sorted array of range descriptors.
 */
static struct bootmem_range bootmem_reserved_ranges[BOOTMEM_MAX_RESERVED_RANGES]
    __bootdata;
static unsigned int bootmem_nr_reserved_ranges __bootdata;

/*
 * Top-down allocations are normally preferred to avoid unnecessarily
 * filling the DMA zone.
 */
struct bootmem_heap {
    phys_addr_t start;
    phys_addr_t end;
    phys_addr_t bottom;
    phys_addr_t top;
    bool topdown;
};

static struct bootmem_heap bootmem_heap __bootdata;

static char bootmem_panic_msg_zone_overlapping[] __bootdata
    = "bootmem: zone overlapping";
static char bootmem_panic_msg_invalid_zone_index_msg[] __bootdata
    = "bootmem: invalid zone index";
static char bootmem_panic_msg_zone_already_registered[] __bootdata
    = "bootmem: zone already registered";
static char bootmem_panic_msg_invalid_reserved_range[] __bootdata
    = "bootmem: invalid reserved range";
static char bootmem_panic_msg_too_many_reserved_ranges[] __bootdata
    = "bootmem: too many reserved ranges";
static char bootmem_panic_msg_setup[] __bootdata
    = "bootmem: unable to set up the early memory allocator";
static char bootmem_panic_msg_nomem[] __bootdata
    = "bootmem: unable to allocate memory";
static char bootmem_panic_msg_invalid_argument[] __bootdata
    = "bootmem: invalid argument";

void * __boot
bootmem_memcpy(void *dest, const void *src, size_t n)
{
    const char *src_ptr;
    char *dest_ptr;

    dest_ptr = dest;
    src_ptr = src;

    for (size_t i = 0; i < n; i++) {
        *dest_ptr = *src_ptr;
        dest_ptr++;
        src_ptr++;
    }

    return dest;
}

void * __boot
bootmem_memmove(void *dest, const void *src, size_t n)
{
    const char *src_ptr;
    char *dest_ptr;

    if (dest <= src) {
        dest_ptr = dest;
        src_ptr = src;

        for (size_t i = 0; i < n; i++) {
            *dest_ptr = *src_ptr;
            dest_ptr++;
            src_ptr++;
        }
    } else {
        dest_ptr = dest + n - 1;
        src_ptr = src + n - 1;

        for (size_t i = 0; i < n; i++) {
            *dest_ptr = *src_ptr;
            dest_ptr--;
            src_ptr--;
        }
    }

    return dest;
}

void * __boot
bootmem_memset(void *s, int c, size_t n)
{
    char *buffer;

    buffer = s;

    for (size_t i = 0; i < n; i++) {
        buffer[i] = c;
    }

    return s;
}

size_t __boot
bootmem_strlen(const char *s)
{
    const char *start;

    start = s;

    while (*s != '\0') {
        s++;
    }

    return (s - start);
}

static bool __boot
bootmem_overlaps(phys_addr_t start1, phys_addr_t end1,
                 phys_addr_t start2, phys_addr_t end2)
{
    return ((end2 > start1) && (start2 < end1));
}

static bool __boot
bootmem_included(phys_addr_t start1, phys_addr_t end1,
                 phys_addr_t start2, phys_addr_t end2)
{
    return ((start2 >= start1) && (end2 <= end1));
}

static void __boot
bootmem_zone_init(struct bootmem_zone *zone, phys_addr_t start,
                  phys_addr_t end, bool direct_mapped)
{
    zone->start = start;
    zone->end = end;
    zone->registered = true;
    zone->direct_mapped = direct_mapped;
}

static phys_addr_t __boot
bootmem_zone_end(const struct bootmem_zone *zone)
{
    return zone->end;
}

static phys_addr_t __boot
bootmem_zone_size(const struct bootmem_zone *zone)
{
    return zone->end - zone->start;
}

static bool __boot
bootmem_zone_registered(const struct bootmem_zone *zone)
{
    return zone->registered;
}

static bool __boot
bootmem_zone_overlaps(const struct bootmem_zone *zone,
                      phys_addr_t start, phys_addr_t end)
{
    return bootmem_overlaps(zone->start, zone->end, start, end);
}

static struct bootmem_zone * __boot
bootmem_get_zone(unsigned int index)
{
    assert(index < ARRAY_SIZE(bootmem_zones));
    return &bootmem_zones[index];
}

void __boot
bootmem_register_zone(unsigned int zone_index, bool direct_mapped,
                      phys_addr_t start, phys_addr_t end)
{
    struct bootmem_zone *zone, *tmp;

    for (size_t i = 0; i < ARRAY_SIZE(bootmem_zones); i++) {
        tmp = bootmem_get_zone(i);

        if (!bootmem_zone_registered(tmp)) {
            continue;
        }

        if (bootmem_zone_overlaps(tmp, start, end)) {
            boot_panic(bootmem_panic_msg_zone_overlapping);
        }
    }

    zone = bootmem_get_zone(zone_index);

    if (zone == NULL) {
        boot_panic(bootmem_panic_msg_invalid_zone_index_msg);
    }

    if (bootmem_zone_registered(zone)) {
        boot_panic(bootmem_panic_msg_zone_already_registered);
    }

    bootmem_zone_init(zone, start, end, direct_mapped);
}

static void __boot
bootmem_range_init(struct bootmem_range *range, phys_addr_t start,
                   phys_addr_t end, bool temporary)
{
    range->start = start;
    range->end = end;
    range->temporary = temporary;
}

static phys_addr_t __boot
bootmem_range_start(const struct bootmem_range *range)
{
    return range->start;
}

static bool __boot
bootmem_range_temporary(const struct bootmem_range *range)
{
    return range->temporary;
}

static void __boot
bootmem_range_clear_temporary(struct bootmem_range *range)
{
    range->temporary = false;
}

static bool __boot
bootmem_range_overlaps(const struct bootmem_range *range,
                       phys_addr_t start, phys_addr_t end)
{
    return bootmem_overlaps(range->start, range->end, start, end);
}

static bool __boot
bootmem_range_included(const struct bootmem_range *range,
                       phys_addr_t start, phys_addr_t end)
{
    return bootmem_included(range->start, range->end, start, end);
}

static int __boot
bootmem_range_clip_region(const struct bootmem_range *range,
                          phys_addr_t *region_start, phys_addr_t *region_end)
{
    phys_addr_t range_start, range_end;

    range_start = vm_page_trunc(range->start);
    range_end = vm_page_round(range->end);

    if (range_end < range->end) {
        boot_panic(bootmem_panic_msg_invalid_reserved_range);
    }

    if ((range_end <= *region_start) || (range_start >= *region_end)) {
        return 0;
    }

    if (range_start > *region_start) {
        *region_end = range_start;
    } else {
        if (range_end >= *region_end) {
            return ERROR_NOMEM;
        }

        *region_start = range_end;
    }

    return 0;
}

static struct bootmem_range * __boot
bootmem_get_reserved_range(unsigned int index)
{
    assert(index < ARRAY_SIZE(bootmem_reserved_ranges));
    return &bootmem_reserved_ranges[index];
}

static void __boot
bootmem_shift_ranges_up(struct bootmem_range *range)
{
    struct bootmem_range *end;
    size_t size;

    end = bootmem_reserved_ranges + ARRAY_SIZE(bootmem_reserved_ranges);
    size = (end - range - 1) * sizeof(*range);
    bootmem_memmove(range + 1, range, size);
}

void __boot
bootmem_reserve_range(phys_addr_t start, phys_addr_t end, bool temporary)
{
    struct bootmem_range *range;

    if (start >= end) {
        boot_panic(bootmem_panic_msg_invalid_reserved_range);
    }

    if (bootmem_nr_reserved_ranges >= ARRAY_SIZE(bootmem_reserved_ranges)) {
        boot_panic(bootmem_panic_msg_too_many_reserved_ranges);
    }

    range = NULL;

    for (unsigned int i = 0; i < bootmem_nr_reserved_ranges; i++) {
        range = bootmem_get_reserved_range(i);

        if (bootmem_range_overlaps(range, start, end)) {
            /*
             * If the range overlaps, check whether it's part of another
             * range. For example, this applies to debugging symbols directly
             * taken from the kernel image.
             */
            if (bootmem_range_included(range, start, end)) {
                /*
                 * If it's completely included, make sure that a permanent
                 * range remains permanent.
                 *
                 * XXX This means that if one big range is first registered
                 * as temporary, and a smaller range inside of it is
                 * registered as permanent, the bigger range becomes
                 * permanent. It's not easy nor useful in practice to do
                 * better than that.
                 */
                if (bootmem_range_temporary(range) != temporary) {
                    bootmem_range_clear_temporary(range);
                }

                return;
            }

            boot_panic(bootmem_panic_msg_invalid_reserved_range);
        }

        if (end <= bootmem_range_start(range)) {
            break;
        }
    }

    if (range == NULL) {
        range = bootmem_reserved_ranges;
    }

    bootmem_shift_ranges_up(range);
    bootmem_range_init(range, start, end, temporary);
    bootmem_nr_reserved_ranges++;
}

static void __boot
bootmem_heap_init(struct bootmem_heap *heap, bool topdown,
                  phys_addr_t start, phys_addr_t end)
{
    heap->start = start;
    heap->end = end;
    heap->bottom = start;
    heap->top = end;
    heap->topdown = topdown;

    bootmem_reserve_range(start, end, false);
}

static void * __boot
bootmem_heap_alloc(struct bootmem_heap *heap, unsigned int nr_pages)
{
    unsigned long addr, size;

    size = vm_page_ptob(nr_pages);

    if (size == 0) {
        boot_panic(bootmem_panic_msg_invalid_argument);
    }

    if (heap->topdown) {
        addr = heap->top - size;

        if ((addr < heap->start) || (addr > heap->top)) {
            boot_panic(bootmem_panic_msg_nomem);
        }

        heap->top = addr;
    } else {
        unsigned long end;

        addr = heap->bottom;
        end = addr + size;

        if ((end > heap->end) || (end < heap->bottom)) {
            boot_panic(bootmem_panic_msg_nomem);
        }

        heap->bottom = end;
    }

    return bootmem_memset((void *)addr, 0, size);
}

static struct bootmem_heap * __boot
bootmem_get_heap(void)
{
    return &bootmem_heap;
}

/*
 * Find available memory.
 *
 * The search starts at the given start address, up to the given end address.
 * If a range is found, it is stored through the region_startp and region_endp
 * pointers.
 *
 * The range boundaries are page-aligned on return.
 */
static int __boot
bootmem_find_avail(phys_addr_t start, phys_addr_t end,
                   phys_addr_t *region_start, phys_addr_t *region_end)
{
    phys_addr_t orig_start;
    int error;

    assert(start <= end);

    orig_start = start;
    start = vm_page_round(start);
    end = vm_page_trunc(end);

    if ((start < orig_start) || (start >= end)) {
        return ERROR_INVAL;
    }

    *region_start = start;
    *region_end = end;

    for (unsigned int i = 0; i < bootmem_nr_reserved_ranges; i++) {
        error = bootmem_range_clip_region(bootmem_get_reserved_range(i),
                                          region_start, region_end);

        if (error) {
            return error;
        }
    }

    return 0;
}

void __boot
bootmem_setup(bool topdown)
{
    phys_addr_t heap_start, heap_end, max_heap_start, max_heap_end;
    phys_addr_t start, end;
    int error;

    bootmem_reserve_range((uintptr_t)&_boot, BOOT_VTOP((uintptr_t)&_end), false);

    /*
     * Find some memory for the heap. Look for the largest unused area in
     * upper memory, carefully avoiding all boot data.
     */
    end = bootmem_directmap_end();

    max_heap_start = 0;
    max_heap_end = 0;
    start = PMEM_RAM_START;

    for (;;) {
        error = bootmem_find_avail(start, end, &heap_start, &heap_end);

        if (error) {
            break;
        }

        if ((heap_end - heap_start) > (max_heap_end - max_heap_start)) {
            max_heap_start = heap_start;
            max_heap_end = heap_end;
        }

        start = heap_end;
    }

    if (max_heap_start >= max_heap_end) {
        boot_panic(bootmem_panic_msg_setup);
    }

    bootmem_heap_init(bootmem_get_heap(), topdown,
                      max_heap_start, max_heap_end);
}

void * __boot
bootmem_alloc(unsigned int nr_pages)
{
    return bootmem_heap_alloc(bootmem_get_heap(), nr_pages);
}

phys_addr_t __boot
bootmem_directmap_end(void)
{
    if (bootmem_zone_size(bootmem_get_zone(PMEM_ZONE_DIRECTMAP)) != 0) {
        return bootmem_zone_end(bootmem_get_zone(PMEM_ZONE_DIRECTMAP));
    } else if (bootmem_zone_size(bootmem_get_zone(PMEM_ZONE_DMA32)) != 0) {
        return bootmem_zone_end(bootmem_get_zone(PMEM_ZONE_DMA32));
    } else {
        return bootmem_zone_end(bootmem_get_zone(PMEM_ZONE_DMA));
    }
}

#if 0
static void __init
bootmem_map_show(void)
{
    const struct bootmem_map_entry *entry, *end;

    log_debug("bootmem: physical memory map:");

    for (entry = bootmem_map, end = entry + bootmem_map_size;
         entry < end;
         entry++)
        log_debug("bootmem: %018llx:%018llx",
                  (unsigned long long)entry->base_addr,
                  (unsigned long long)(entry->base_addr + entry->length));

    log_debug("bootmem: heap: %llx:%llx",
              (unsigned long long)bootmem_heap_start,
              (unsigned long long)bootmem_heap_end);
}
#endif
