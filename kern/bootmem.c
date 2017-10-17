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
#include <machine/page.h>
#include <machine/pmem.h>
#include <machine/types.h>
#include <vm/vm_kmem.h>
#include <vm/vm_page.h>

#define BOOTMEM_MAX_RESERVED_RANGES 64

#if BOOT_MEM_BLOCK_BITS > PAGE_BITS
#error "block size too large"
#endif

#define BOOTMEM_BLOCK_SIZE (1 << BOOT_MEM_BLOCK_BITS)

/*
 * Special order value for pages that aren't in a free list. Such blocks are
 * either allocated, or part of a free block of pages but not the head page.
 */
#define BOOTMEM_ORDER_UNLISTED ((unsigned short)-1)

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
 * The boundary addresses must not be fixed up, since ranges may overlap the
 * same pages.
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

struct bootmem_block {
    uintptr_t phys_addr;
    struct bootmem_block *next;
    struct bootmem_block **pprev;
    unsigned short order;
    bool allocated;
};

struct bootmem_free_list {
    struct bootmem_block *blocks;
};

struct bootmem_heap {
    phys_addr_t start;
    phys_addr_t end;
    struct bootmem_block *blocks;
    struct bootmem_block *blocks_end;
    struct bootmem_free_list free_lists[BOOT_MEM_NR_FREE_LISTS];
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

static uintptr_t __boot
bootmem_block_round(uintptr_t size)
{
    return P2ROUND(size, BOOTMEM_BLOCK_SIZE);
}

static uintptr_t __boot
bootmem_byte2block(uintptr_t byte)
{
    return byte >> BOOT_MEM_BLOCK_BITS;
}

static uintptr_t __boot
bootmem_block2byte(uintptr_t block)
{
    return block << BOOT_MEM_BLOCK_BITS;
}

static uintptr_t __boot
bootmem_compute_blocks(uintptr_t start, uintptr_t end)
{
    return bootmem_byte2block(end - start);
}

static uintptr_t __boot
bootmem_compute_table_size(uintptr_t nr_blocks)
{
    return bootmem_block_round(nr_blocks * sizeof(struct bootmem_block));
}

static void __boot
bootmem_block_init(struct bootmem_block *block, uintptr_t pa)
{
    block->phys_addr = pa;
    block->order = BOOTMEM_ORDER_UNLISTED;
    block->allocated = true;
}

static void __boot
bootmem_free_list_init(struct bootmem_free_list *list)
{
    list->blocks = NULL;
}

static bool __boot
bootmem_free_list_empty(const struct bootmem_free_list *list)
{
    return list->blocks == NULL;
}

static void __boot
bootmem_free_list_insert(struct bootmem_free_list *list,
                         struct bootmem_block *block)
{
    struct bootmem_block *blocks;

    blocks = list->blocks;
    block->next = blocks;
    block->pprev = &list->blocks;

    if (blocks != NULL) {
        blocks->pprev = &block->next;
    }

    list->blocks = block;
}

static void __boot
bootmem_free_list_remove(struct bootmem_block *block)
{
    if (block->next != NULL) {
        block->next->pprev = block->pprev;
    }

    *block->pprev = block->next;
}

static struct bootmem_block * __boot
bootmem_free_list_pop(struct bootmem_free_list *list)
{
    struct bootmem_block *block;

    block = list->blocks;
    bootmem_free_list_remove(block);
    return block;
}

static struct bootmem_free_list * __boot
bootmem_heap_get_free_list(struct bootmem_heap *heap, unsigned int index)
{
    assert(index < ARRAY_SIZE(heap->free_lists));
    return &heap->free_lists[index];
}

static struct bootmem_block * __boot
bootmem_heap_get_block(struct bootmem_heap *heap, uintptr_t pa)
{
    return &heap->blocks[bootmem_byte2block(pa - heap->start)];
}

static void __boot
bootmem_heap_free(struct bootmem_heap *heap, struct bootmem_block *block,
                  unsigned short order)
{
    struct bootmem_block *buddy;
    uintptr_t pa, buddy_pa;

    assert(block >= heap->blocks);
    assert(block < heap->blocks_end);
    assert(block->order == BOOTMEM_ORDER_UNLISTED);
    assert(order < BOOTMEM_ORDER_UNLISTED);
    assert(block->allocated);

    block->allocated = false;
    pa = block->phys_addr;

    while (order < (BOOT_MEM_NR_FREE_LISTS - 1)) {
        buddy_pa = pa ^ bootmem_block2byte(1 << order);

        if ((buddy_pa < heap->start) || (buddy_pa >= heap->end)) {
            break;
        }

        buddy = &heap->blocks[bootmem_byte2block(buddy_pa - heap->start)];

        if (buddy->order != order) {
            break;
        }

        bootmem_free_list_remove(buddy);
        buddy->order = BOOTMEM_ORDER_UNLISTED;
        order++;
        pa &= -bootmem_block2byte(1 << order); /* TODO Function */
        block = &heap->blocks[bootmem_byte2block(pa - heap->start)];
    }

    bootmem_free_list_insert(&heap->free_lists[order], block);
    block->order = order;
}

static struct bootmem_block * __boot
bootmem_heap_alloc(struct bootmem_heap *heap, unsigned short order)
{
    struct bootmem_free_list *free_list;
    struct bootmem_block *block, *buddy;
    unsigned int i;

    assert(order < BOOT_MEM_NR_FREE_LISTS);

    for (i = order; i < BOOT_MEM_NR_FREE_LISTS; i++) {
        free_list = &heap->free_lists[i];

        if (!bootmem_free_list_empty(free_list)) {
            break;
        }
    }

    if (i == BOOT_MEM_NR_FREE_LISTS) {
        return NULL;
    }

    block = bootmem_free_list_pop(free_list);
    block->order = BOOTMEM_ORDER_UNLISTED;

    while (i > order) {
        i--;
        buddy = &block[1 << i];
        bootmem_free_list_insert(bootmem_heap_get_free_list(heap, i), buddy);
        buddy->order = i;
    }

    return block;
}

static void __boot
bootmem_heap_init(struct bootmem_heap *heap, uintptr_t start, uintptr_t end)
{
    uintptr_t heap_blocks, table_size, table_blocks;

    bootmem_reserve_range(start, end, false);

    heap->start = start;
    heap->end = end;
    heap_blocks = bootmem_compute_blocks(start, end);
    table_size = bootmem_compute_table_size(heap_blocks);
    assert((end - table_size) > start);
    heap->blocks = (struct bootmem_block *)(end - table_size);
    heap->blocks_end = &heap->blocks[heap_blocks];

    for (size_t i = 0; i < ARRAY_SIZE(heap->free_lists); i++) {
        bootmem_free_list_init(&heap->free_lists[i]);
    }

    for (phys_addr_t pa = start; pa < end; pa += BOOTMEM_BLOCK_SIZE) {
        bootmem_block_init(bootmem_heap_get_block(heap, pa), pa);
    }

    table_blocks = bootmem_byte2block(table_size);
    heap_blocks -= table_blocks;

    for (size_t i = 0; i < heap_blocks; i++) {
        bootmem_heap_free(heap, &heap->blocks[i], 0);
    }
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
bootmem_setup(void)
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

    assert(max_heap_start == (uintptr_t)max_heap_start);
    assert(max_heap_end == (uintptr_t)max_heap_end);
    bootmem_heap_init(bootmem_get_heap(), max_heap_start, max_heap_end);
}

static unsigned short __boot
bootmem_alloc_order(size_t size)
{
    return iorder2(bootmem_byte2block(bootmem_block_round(size)));
}

void * __boot
bootmem_alloc(size_t size)
{
    struct bootmem_block *block;

    block = bootmem_heap_alloc(bootmem_get_heap(), bootmem_alloc_order(size));

    if (block == NULL) {
        boot_panic(bootmem_panic_msg_nomem);
    }

    return (void *)block->phys_addr;
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
