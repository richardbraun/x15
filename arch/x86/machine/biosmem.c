/*
 * Copyright (c) 2010-2016 Richard Braun.
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

#include <kern/assert.h>
#include <kern/init.h>
#include <kern/macros.h>
#include <kern/panic.h>
#include <kern/param.h>
#include <kern/printk.h>
#include <kern/stddef.h>
#include <kern/stdint.h>
#include <kern/string.h>
#include <kern/types.h>
#include <machine/biosmem.h>
#include <machine/boot.h>
#include <machine/cpu.h>
#include <machine/elf.h>
#include <machine/multiboot.h>
#include <vm/vm_kmem.h>
#include <vm/vm_page.h>

#define DEBUG 0

/*
 * Maximum number of entries in the BIOS memory map.
 *
 * Because of adjustments of overlapping ranges, the memory map can grow
 * to twice this size.
 */
#define BIOSMEM_MAX_MAP_SIZE 128

/*
 * Memory range types.
 */
#define BIOSMEM_TYPE_AVAILABLE  1
#define BIOSMEM_TYPE_RESERVED   2
#define BIOSMEM_TYPE_ACPI       3
#define BIOSMEM_TYPE_NVS        4
#define BIOSMEM_TYPE_UNUSABLE   5
#define BIOSMEM_TYPE_DISABLED   6

/*
 * Memory map entry.
 */
struct biosmem_map_entry {
    uint64_t base_addr;
    uint64_t length;
    unsigned int type;
};

/*
 * Contiguous block of physical memory.
 */
struct biosmem_segment {
    phys_addr_t start;
    phys_addr_t end;
};

/*
 * Memory map built from the information passed by the boot loader.
 *
 * If the boot loader didn't pass a valid memory map, a simple map is built
 * based on the mem_lower and mem_upper multiboot fields.
 */
static struct biosmem_map_entry biosmem_map[BIOSMEM_MAX_MAP_SIZE * 2]
    __bootdata;
static unsigned int biosmem_map_size __bootdata;

/*
 * Physical segment boundaries.
 */
static struct biosmem_segment biosmem_segments[VM_PAGE_MAX_SEGS] __bootdata;

/*
 * Boundaries of the simple bootstrap heap.
 *
 * This heap is located above BIOS memory.
 */
static uint32_t biosmem_heap_start __bootdata;
static uint32_t biosmem_heap_bottom __bootdata;
static uint32_t biosmem_heap_top __bootdata;
static uint32_t biosmem_heap_end __bootdata;

/*
 * Boot allocation policy.
 *
 * Top-down allocations are normally preferred to avoid unnecessarily
 * filling the DMA segment.
 */
static bool biosmem_heap_topdown __bootdata;

static char biosmem_panic_toobig_msg[] __bootdata
    = "biosmem: too many memory map entries";
static char biosmem_panic_setup_msg[] __bootdata
    = "biosmem: unable to set up the early memory allocator";
static char biosmem_panic_noseg_msg[] __bootdata
    = "biosmem: unable to find any memory segment";
static char biosmem_panic_inval_msg[] __bootdata
    = "biosmem: attempt to allocate 0 page";
static char biosmem_panic_nomem_msg[] __bootdata
    = "biosmem: unable to allocate memory";

static void __boot
biosmem_map_build(const struct multiboot_raw_info *mbi)
{
    struct multiboot_raw_mmap_entry *mb_entry, *mb_end;
    struct biosmem_map_entry *start, *entry, *end;
    unsigned long addr;

    addr = mbi->mmap_addr;
    mb_entry = (struct multiboot_raw_mmap_entry *)addr;
    mb_end = (struct multiboot_raw_mmap_entry *)(addr + mbi->mmap_length);
    start = biosmem_map;
    entry = start;
    end = entry + BIOSMEM_MAX_MAP_SIZE;

    while ((mb_entry < mb_end) && (entry < end)) {
        entry->base_addr = mb_entry->base_addr;
        entry->length = mb_entry->length;
        entry->type = mb_entry->type;

        mb_entry = (void *)mb_entry + sizeof(mb_entry->size) + mb_entry->size;
        entry++;
    }

    biosmem_map_size = entry - start;
}

static void __boot
biosmem_map_build_simple(const struct multiboot_raw_info *mbi)
{
    struct biosmem_map_entry *entry;

    entry = biosmem_map;
    entry->base_addr = 0;
    entry->length = mbi->mem_lower << 10;
    entry->type = BIOSMEM_TYPE_AVAILABLE;

    entry++;
    entry->base_addr = BIOSMEM_END;
    entry->length = mbi->mem_upper << 10;
    entry->type = BIOSMEM_TYPE_AVAILABLE;

    biosmem_map_size = 2;
}

static int __boot
biosmem_map_entry_is_invalid(const struct biosmem_map_entry *entry)
{
    return (entry->base_addr + entry->length) <= entry->base_addr;
}

static void __boot
biosmem_map_filter(void)
{
    struct biosmem_map_entry *entry;
    unsigned int i;

    i = 0;

    while (i < biosmem_map_size) {
        entry = &biosmem_map[i];

        if (biosmem_map_entry_is_invalid(entry)) {
            biosmem_map_size--;
            boot_memmove(entry, entry + 1,
                         (biosmem_map_size - i) * sizeof(*entry));
            continue;
        }

        i++;
    }
}

static void __boot
biosmem_map_sort(void)
{
    struct biosmem_map_entry tmp;
    unsigned int i, j;

    /*
     * Simple insertion sort.
     */
    for (i = 1; i < biosmem_map_size; i++) {
        tmp = biosmem_map[i];

        for (j = i - 1; j < i; j--) {
            if (biosmem_map[j].base_addr < tmp.base_addr)
                break;

            biosmem_map[j + 1] = biosmem_map[j];
        }

        biosmem_map[j + 1] = tmp;
    }
}

static void __boot
biosmem_map_adjust(void)
{
    struct biosmem_map_entry tmp, *a, *b, *first, *second;
    uint64_t a_end, b_end, last_end;
    unsigned int i, j, last_type;

    biosmem_map_filter();

    /*
     * Resolve overlapping areas, giving priority to most restrictive
     * (i.e. numerically higher) types.
     */
    for (i = 0; i < biosmem_map_size; i++) {
        a = &biosmem_map[i];
        a_end = a->base_addr + a->length;

        j = i + 1;

        while (j < biosmem_map_size) {
            b = &biosmem_map[j];
            b_end = b->base_addr + b->length;

            if ((a->base_addr >= b_end) || (a_end <= b->base_addr)) {
                j++;
                continue;
            }

            if (a->base_addr < b->base_addr) {
                first = a;
                second = b;
            } else {
                first = b;
                second = a;
            }

            if (a_end > b_end) {
                last_end = a_end;
                last_type = a->type;
            } else {
                last_end = b_end;
                last_type = b->type;
            }

            tmp.base_addr = second->base_addr;
            tmp.length = MIN(a_end, b_end) - tmp.base_addr;
            tmp.type = MAX(a->type, b->type);
            first->length = tmp.base_addr - first->base_addr;
            second->base_addr += tmp.length;
            second->length = last_end - second->base_addr;
            second->type = last_type;

            /*
             * Filter out invalid entries.
             */
            if (biosmem_map_entry_is_invalid(a)
                && biosmem_map_entry_is_invalid(b)) {
                *a = tmp;
                biosmem_map_size--;
                memmove(b, b + 1, (biosmem_map_size - j) * sizeof(*b));
                continue;
            } else if (biosmem_map_entry_is_invalid(a)) {
                *a = tmp;
                j++;
                continue;
            } else if (biosmem_map_entry_is_invalid(b)) {
                *b = tmp;
                j++;
                continue;
            }

            if (tmp.type == a->type)
                first = a;
            else if (tmp.type == b->type)
                first = b;
            else {

                /*
                 * If the overlapping area can't be merged with one of its
                 * neighbors, it must be added as a new entry.
                 */

                if (biosmem_map_size >= ARRAY_SIZE(biosmem_map))
                    boot_panic(biosmem_panic_toobig_msg);

                biosmem_map[biosmem_map_size] = tmp;
                biosmem_map_size++;
                j++;
                continue;
            }

            if (first->base_addr > tmp.base_addr)
                first->base_addr = tmp.base_addr;

            first->length += tmp.length;
            j++;
        }
    }

    biosmem_map_sort();
}

static int __boot
biosmem_map_find_avail(phys_addr_t *phys_start, phys_addr_t *phys_end)
{
    const struct biosmem_map_entry *entry, *map_end;
    phys_addr_t seg_start, seg_end;
    uint64_t start, end;

    seg_start = (phys_addr_t)-1;
    seg_end = (phys_addr_t)-1;
    map_end = biosmem_map + biosmem_map_size;

    for (entry = biosmem_map; entry < map_end; entry++) {
        if (entry->type != BIOSMEM_TYPE_AVAILABLE)
            continue;

        start = vm_page_round(entry->base_addr);

        if (start >= *phys_end)
            break;

        end = vm_page_trunc(entry->base_addr + entry->length);

        if ((start < end) && (start < *phys_end) && (end > *phys_start)) {
            if (seg_start == (phys_addr_t)-1)
                seg_start = start;

            seg_end = end;
        }
    }

    if ((seg_start == (phys_addr_t)-1) || (seg_end == (phys_addr_t)-1))
        return -1;

    if (seg_start > *phys_start)
        *phys_start = seg_start;

    if (seg_end < *phys_end)
        *phys_end = seg_end;

    return 0;
}

static void __boot
biosmem_set_segment(unsigned int seg_index, phys_addr_t start, phys_addr_t end)
{
    biosmem_segments[seg_index].start = start;
    biosmem_segments[seg_index].end = end;
}

static phys_addr_t __boot
biosmem_segment_end(unsigned int seg_index)
{
    return biosmem_segments[seg_index].end;
}

static phys_addr_t __boot
biosmem_segment_size(unsigned int seg_index)
{
    return biosmem_segments[seg_index].end - biosmem_segments[seg_index].start;
}

static void __boot
biosmem_save_cmdline_sizes(struct multiboot_raw_info *mbi)
{
    struct multiboot_raw_module *mod;
    uint32_t i;

    if (mbi->flags & MULTIBOOT_LOADER_CMDLINE)
        mbi->unused0 = boot_strlen((char *)(unsigned long)mbi->cmdline) + 1;

    if (mbi->flags & MULTIBOOT_LOADER_MODULES) {
        unsigned long addr;

        addr = mbi->mods_addr;

        for (i = 0; i < mbi->mods_count; i++) {
            mod = (struct multiboot_raw_module *)addr + i;
            mod->reserved = boot_strlen((char *)(unsigned long)mod->string) + 1;
        }
    }
}

static int __boot
biosmem_find_heap_clip(uint32_t *heap_start, uint32_t *heap_end,
                       uint32_t data_start, uint32_t data_end)
{
    assert(data_start < data_end);

    if ((data_end <= *heap_start) || (data_start >= *heap_end)) {
        return 0;
    }

    if (data_start > *heap_start) {
        *heap_end = data_start;
    } else {
        if (data_end >= *heap_end) {
            return -1;
        }

        *heap_start = data_end;
    }

    return 0;
}

/*
 * Find available memory for an allocation heap.
 *
 * The search starts at the given start address, up to the given end address.
 * If a range is found, it is stored through the heap_startp and heap_endp
 * pointers.
 *
 * The search skips boot data, that is :
 *  - the kernel
 *  - the kernel command line
 *  - the module table
 *  - the modules
 *  - the modules command lines
 *  - the ELF section header table
 *  - the ELF .shstrtab, .symtab and .strtab sections
 */
static int __boot
biosmem_find_heap(const struct multiboot_raw_info *mbi,
                  uint32_t start, uint32_t end,
                  uint32_t *heap_start, uint32_t *heap_end)
{
    struct multiboot_raw_module *mod;
    struct elf_shdr *shdr;
    unsigned long tmp;
    uint32_t i;
    int error;

    if (start >= end) {
        return -1;
    }

    *heap_start = start;
    *heap_end = end;

    error = biosmem_find_heap_clip(heap_start, heap_end,
                                   (unsigned long)&_boot,
                                   BOOT_VTOP((unsigned long)&_end));

    if (error) {
        return error;
    }

    if ((mbi->flags & MULTIBOOT_LOADER_CMDLINE) && (mbi->cmdline != 0)) {
        error = biosmem_find_heap_clip(heap_start, heap_end,
                                       mbi->cmdline,
                                       mbi->cmdline + mbi->unused0);

        if (error) {
            return error;
        }
    }

    if (mbi->flags & MULTIBOOT_LOADER_MODULES) {
        i = mbi->mods_count * sizeof(struct multiboot_raw_module);
        error = biosmem_find_heap_clip(heap_start, heap_end,
                                       mbi->mods_addr, mbi->mods_addr + i);

        if (error) {
            return error;
        }

        tmp = mbi->mods_addr;

        for (i = 0; i < mbi->mods_count; i++) {
            mod = (struct multiboot_raw_module *)tmp + i;
            error = biosmem_find_heap_clip(heap_start, heap_end,
                                           mod->mod_start, mod->mod_end);

            if (error) {
                return error;
            }

            if (mod->string != 0) {
                error = biosmem_find_heap_clip(heap_start, heap_end,
                                               mod->string,
                                               mod->string + mod->reserved);

                if (error) {
                    return error;
                }
            }
        }
    }

    if (mbi->flags & MULTIBOOT_LOADER_SHDR) {
        tmp = mbi->shdr_num * mbi->shdr_size;
        error = biosmem_find_heap_clip(heap_start, heap_end,
                                       mbi->shdr_addr, mbi->shdr_addr + tmp);

        if (error) {
            return error;
        }

        tmp = mbi->shdr_addr;

        for (i = 0; i < mbi->shdr_num; i++) {
            shdr = (struct elf_shdr *)(tmp + (i * mbi->shdr_size));

            if ((shdr->type != ELF_SHT_SYMTAB)
                && (shdr->type != ELF_SHT_STRTAB))
                continue;

            error = biosmem_find_heap_clip(heap_start, heap_end,
                                           shdr->addr, shdr->addr + shdr->size);
        }
    }

    return 0;
}

static void __boot
biosmem_setup_allocator(struct multiboot_raw_info *mbi)
{
    uint32_t heap_start, heap_end, max_heap_start, max_heap_end;
    uint32_t start, end;
    int error;

    /*
     * Find some memory for the heap. Look for the largest unused area in
     * upper memory, carefully avoiding all boot data.
     */
    end = vm_page_trunc((mbi->mem_upper + 1024) << 10);

#ifndef __LP64__
    if (end > VM_PAGE_DIRECTMAP_LIMIT)
        end = VM_PAGE_DIRECTMAP_LIMIT;
#endif /* __LP64__ */

    max_heap_start = 0;
    max_heap_end = 0;
    start = BIOSMEM_END;

    for (;;) {
        error = biosmem_find_heap(mbi, start, end, &heap_start, &heap_end);

        if (error) {
            break;
        }

        if ((heap_end - heap_start) > (max_heap_end - max_heap_start)) {
            max_heap_start = heap_start;
            max_heap_end = heap_end;
        }

        start = heap_end;
    }

    if (max_heap_start >= max_heap_end)
        boot_panic(biosmem_panic_setup_msg);

    max_heap_start = vm_page_round(max_heap_start);
    max_heap_end = vm_page_trunc(max_heap_end);

    if (max_heap_start >= max_heap_end)
        boot_panic(biosmem_panic_setup_msg);

    biosmem_heap_start = max_heap_start;
    biosmem_heap_end = max_heap_end;
    biosmem_heap_bottom = biosmem_heap_start;
    biosmem_heap_top = biosmem_heap_end;
    biosmem_heap_topdown = true;
}

void __boot
biosmem_bootstrap(struct multiboot_raw_info *mbi)
{
    phys_addr_t phys_start, phys_end;
    int error;

    if (mbi->flags & MULTIBOOT_LOADER_MMAP)
        biosmem_map_build(mbi);
    else
        biosmem_map_build_simple(mbi);

    biosmem_map_adjust();

    phys_start = BIOSMEM_BASE;
    phys_end = VM_PAGE_DMA_LIMIT;
    error = biosmem_map_find_avail(&phys_start, &phys_end);

    if (error)
        boot_panic(biosmem_panic_noseg_msg);

    biosmem_set_segment(VM_PAGE_SEG_DMA, phys_start, phys_end);

    phys_start = VM_PAGE_DMA_LIMIT;
#ifdef VM_PAGE_DMA32_LIMIT
    phys_end = VM_PAGE_DMA32_LIMIT;
    error = biosmem_map_find_avail(&phys_start, &phys_end);

    if (error)
        goto out;

    biosmem_set_segment(VM_PAGE_SEG_DMA32, phys_start, phys_end);

    phys_start = VM_PAGE_DMA32_LIMIT;
#endif /* VM_PAGE_DMA32_LIMIT */
    phys_end = VM_PAGE_DIRECTMAP_LIMIT;
    error = biosmem_map_find_avail(&phys_start, &phys_end);

    if (error)
        goto out;

    biosmem_set_segment(VM_PAGE_SEG_DIRECTMAP, phys_start, phys_end);

    phys_start = VM_PAGE_DIRECTMAP_LIMIT;
    phys_end = VM_PAGE_HIGHMEM_LIMIT;
    error = biosmem_map_find_avail(&phys_start, &phys_end);

    if (error)
        goto out;

    biosmem_set_segment(VM_PAGE_SEG_HIGHMEM, phys_start, phys_end);

out:

    /*
     * The kernel and modules command lines will be memory mapped later
     * during initialization. Their respective sizes must be saved.
     */
    biosmem_save_cmdline_sizes(mbi);
    biosmem_setup_allocator(mbi);
}

void * __boot
biosmem_bootalloc(unsigned int nr_pages)
{
    unsigned long addr, size;

    size = vm_page_ptoa(nr_pages);

    if (size == 0)
        boot_panic(biosmem_panic_inval_msg);

    if (biosmem_heap_topdown) {
        addr = biosmem_heap_top - size;

        if ((addr < biosmem_heap_start) || (addr > biosmem_heap_top)) {
            boot_panic(biosmem_panic_nomem_msg);
        }

        biosmem_heap_top = addr;
    } else {
        unsigned long end;

        addr = biosmem_heap_bottom;
        end = addr + size;

        if ((end > biosmem_heap_end) || (end < biosmem_heap_bottom)) {
            boot_panic(biosmem_panic_nomem_msg);
        }

        biosmem_heap_bottom = end;
    }

    return boot_memset((void *)addr, 0, size);
}

void __boot
biosmem_set_bootalloc_policy(bool topdown)
{
    biosmem_heap_topdown = topdown;
}

phys_addr_t __boot
biosmem_directmap_end(void)
{
    if (biosmem_segment_size(VM_PAGE_SEG_DIRECTMAP) != 0)
        return biosmem_segment_end(VM_PAGE_SEG_DIRECTMAP);
    else if (biosmem_segment_size(VM_PAGE_SEG_DMA32) != 0)
        return biosmem_segment_end(VM_PAGE_SEG_DMA32);
    else
        return biosmem_segment_end(VM_PAGE_SEG_DMA);
}

static const char * __init
biosmem_type_desc(unsigned int type)
{
    switch (type) {
    case BIOSMEM_TYPE_AVAILABLE:
        return "available";
    case BIOSMEM_TYPE_RESERVED:
        return "reserved";
    case BIOSMEM_TYPE_ACPI:
        return "ACPI";
    case BIOSMEM_TYPE_NVS:
        return "ACPI NVS";
    case BIOSMEM_TYPE_UNUSABLE:
        return "unusable";
    default:
        return "unknown (reserved)";
    }
}

static void __init
biosmem_map_show(void)
{
    const struct biosmem_map_entry *entry, *end;

    printk("biosmem: physical memory map:\n");

    for (entry = biosmem_map, end = entry + biosmem_map_size;
         entry < end;
         entry++)
        printk("biosmem: %018llx:%018llx, %s\n", entry->base_addr,
               entry->base_addr + entry->length,
               biosmem_type_desc(entry->type));

    printk("biosmem: heap: %x-%x\n", biosmem_heap_start, biosmem_heap_end);
}

static void __init
biosmem_load_segment(struct biosmem_segment *seg, uint64_t max_phys_end)
{
    phys_addr_t phys_start, phys_end, avail_start, avail_end;
    unsigned int seg_index;

    phys_start = seg->start;
    phys_end = seg->end;
    seg_index = seg - biosmem_segments;

    if (phys_end > max_phys_end) {
        if (max_phys_end <= phys_start) {
            printk("biosmem: warning: segment %s physically unreachable, "
                   "not loaded\n", vm_page_seg_name(seg_index));
            return;
        }

        printk("biosmem: warning: segment %s truncated to %#llx\n",
               vm_page_seg_name(seg_index), max_phys_end);
        phys_end = max_phys_end;
    }

    vm_page_load(seg_index, phys_start, phys_end);

    /*
     * Clip the remaining available heap to fit it into the loaded
     * segment if possible.
     */

    if ((biosmem_heap_top > phys_start) && (biosmem_heap_bottom < phys_end)) {
        if (biosmem_heap_bottom >= phys_start) {
            avail_start = biosmem_heap_bottom;
        } else {
            avail_start = phys_start;
        }

        if (biosmem_heap_top <= phys_end) {
            avail_end = biosmem_heap_top;
        } else {
            avail_end = phys_end;
        }

        vm_page_load_heap(seg_index, avail_start, avail_end);
    }
}

void __init
biosmem_setup(void)
{
    uint64_t max_phys_end;
    struct biosmem_segment *seg;
    struct cpu *cpu;
    unsigned int i;

    biosmem_map_show();

    cpu = cpu_current();
    max_phys_end = (cpu->phys_addr_width == 0)
                   ? (uint64_t)-1
                   : (uint64_t)1 << cpu->phys_addr_width;

    for (i = 0; i < ARRAY_SIZE(biosmem_segments); i++) {
        if (biosmem_segment_size(i) == 0)
            break;

        seg = &biosmem_segments[i];
        biosmem_load_segment(seg, max_phys_end);
    }
}

static void __init
biosmem_free_usable_range(phys_addr_t start, phys_addr_t end)
{
    struct vm_page *page;

#if DEBUG
    printk("biosmem: release to vm_page: %llx-%llx (%lluk)\n",
           (unsigned long long)start, (unsigned long long)end,
           (unsigned long long)((end - start) >> 10));
#endif

    while (start < end) {
        page = vm_page_lookup(start);
        assert(page != NULL);
        vm_page_manage(page);
        start += PAGE_SIZE;
    }
}

static void __init
biosmem_free_usable_skip(phys_addr_t *start, phys_addr_t res_start,
                         phys_addr_t res_end)
{
    if ((*start >= res_start) && (*start < res_end))
        *start = res_end;
}

static phys_addr_t __init
biosmem_free_usable_start(phys_addr_t start)
{
    biosmem_free_usable_skip(&start, (unsigned long)&_boot,
                             BOOT_VTOP((unsigned long)&_end));
    biosmem_free_usable_skip(&start, biosmem_heap_start, biosmem_heap_end);
    return start;
}

static int __init
biosmem_free_usable_reserved(phys_addr_t addr)
{
    if ((addr >= (unsigned long)&_boot)
        && (addr < BOOT_VTOP((unsigned long)&_end)))
        return 1;

    if ((addr >= biosmem_heap_start) && (addr < biosmem_heap_end))
        return 1;

    return 0;
}

static phys_addr_t __init
biosmem_free_usable_end(phys_addr_t start, phys_addr_t entry_end)
{
    while (start < entry_end) {
        if (biosmem_free_usable_reserved(start))
            break;

        start += PAGE_SIZE;
    }

    return start;
}

static void __init
biosmem_free_usable_entry(phys_addr_t start, phys_addr_t end)
{
    phys_addr_t entry_end;

    entry_end = end;

    for (;;) {
        start = biosmem_free_usable_start(start);

        if (start >= entry_end)
            return;

        end = biosmem_free_usable_end(start, entry_end);
        biosmem_free_usable_range(start, end);
        start = end;
    }
}

void __init
biosmem_free_usable(void)
{
    struct biosmem_map_entry *entry;
    uint64_t start, end;
    unsigned int i;

    for (i = 0; i < biosmem_map_size; i++) {
        entry = &biosmem_map[i];

        if (entry->type != BIOSMEM_TYPE_AVAILABLE)
            continue;

        start = vm_page_round(entry->base_addr);

        if (start >= VM_PAGE_HIGHMEM_LIMIT)
            break;

        end = vm_page_trunc(entry->base_addr + entry->length);

        if (end > VM_PAGE_HIGHMEM_LIMIT) {
            end = VM_PAGE_HIGHMEM_LIMIT;
        }

        if (start < BIOSMEM_BASE)
            start = BIOSMEM_BASE;

        if (start >= end) {
            continue;
        }

        biosmem_free_usable_entry(start, end);
    }
}
