/*
 * Copyright (c) 2010, 2011, 2012 Richard Braun.
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
 * Memory map built from the information passed by the boot loader.
 *
 * If the boot loader didn't pass a valid memory map, a simple map is built
 * based on the mem_lower and mem_upper multiboot fields.
 */
static struct biosmem_map_entry biosmem_map[BIOSMEM_MAX_MAP_SIZE * 2]
    __bootdata;

/*
 * Number of valid entries in the BIOS memory map table.
 */
static unsigned int biosmem_map_size __bootdata;

/*
 * Boundaries of the simple bootstrap heap.
 */
static uint32_t biosmem_heap_start __bootdata;
static uint32_t biosmem_heap_free __bootdata;
static uint32_t biosmem_heap_end __bootdata;

static char biosmem_panic_setup_msg[] __bootdata
    = "biosmem: unable to set up the early memory allocator";
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

static void __boot
biosmem_find_boot_data_update(uint32_t min, uint32_t *start, uint32_t *end,
                              uint32_t data_start, uint32_t data_end)
{
    if ((min <= data_start) && (data_start < *start)) {
        *start = data_start;
        *end = data_end;
    }
}

/*
 * Find the first boot data in the given range, and return their containing
 * area (start address is returned directly, end address is returned in end).
 * The following are considered boot data :
 *  - the kernel
 *  - the kernel command line
 *  - the module table
 *  - the modules
 *  - the modules command lines
 *  - the ELF section header table
 *  - the ELF .shstrtab, .symtab and .strtab sections
 *
 * If no boot data was found, 0 is returned, and the end address isn't set.
 */
static uint32_t __boot
biosmem_find_boot_data(const struct multiboot_raw_info *mbi, uint32_t min,
                       uint32_t max, uint32_t *endp)
{
    struct multiboot_raw_module *mod;
    struct elf_shdr *shdr;
    uint32_t i, start, end = end;
    unsigned long tmp;

    start = max;

    biosmem_find_boot_data_update(min, &start, &end, (unsigned long)&_boot,
                                  BOOT_VTOP((unsigned long)&_end));

    if ((mbi->flags & MULTIBOOT_LOADER_CMDLINE) && (mbi->cmdline != 0))
        biosmem_find_boot_data_update(min, &start, &end, mbi->cmdline,
                                      mbi->cmdline + mbi->unused0);

    if (mbi->flags & MULTIBOOT_LOADER_MODULES) {
        i = mbi->mods_count * sizeof(struct multiboot_raw_module);
        biosmem_find_boot_data_update(min, &start, &end, mbi->mods_addr,
                                      mbi->mods_addr + i);
        tmp = mbi->mods_addr;

        for (i = 0; i < mbi->mods_count; i++) {
            mod = (struct multiboot_raw_module *)tmp + i;
            biosmem_find_boot_data_update(min, &start, &end, mod->mod_start,
                                          mod->mod_end);

            if (mod->string != 0)
                biosmem_find_boot_data_update(min, &start, &end, mod->string,
                                              mod->string + mod->reserved);
        }
    }

    if (mbi->flags & MULTIBOOT_LOADER_SHDR) {
        tmp = mbi->shdr_num * mbi->shdr_size;
        biosmem_find_boot_data_update(min, &start, &end, mbi->shdr_addr,
                                      mbi->shdr_addr + tmp);
        tmp = mbi->shdr_addr;

        for (i = 0; i < mbi->shdr_num; i++) {
            shdr = (struct elf_shdr *)(tmp + (i * mbi->shdr_size));

            if ((shdr->type != ELF_SHT_SYMTAB)
                && (shdr->type != ELF_SHT_STRTAB))
                continue;

            biosmem_find_boot_data_update(min, &start, &end, shdr->addr,
                                          shdr->addr + shdr->size);
        }
    }

    if (start == max)
        return 0;

    *endp = end;
    return start;
}

static void __boot
biosmem_setup_allocator(struct multiboot_raw_info *mbi)
{
    uint32_t heap_start, heap_end, max_heap_start, max_heap_end;
    uint32_t mem_end, next;

    /*
     * Find some memory for the heap. Look for the largest unused area in
     * upper memory, carefully avoiding all boot data.
     */
    mem_end = vm_page_trunc((mbi->mem_upper + 1024) << 10);
    max_heap_start = 0;
    max_heap_end = 0;
    next = BIOSMEM_END;

    do {
        heap_start = next;
        heap_end = biosmem_find_boot_data(mbi, heap_start, mem_end, &next);

        if (heap_end == 0) {
            heap_end = mem_end;
            next = 0;
        }

        if ((heap_end - heap_start) > (max_heap_end - max_heap_start)) {
            max_heap_start = heap_start;
            max_heap_end = heap_end;
        }
    } while (next != 0);

    max_heap_start = vm_page_round(max_heap_start);
    max_heap_end = vm_page_trunc(max_heap_end);

    if (max_heap_start >= max_heap_end)
        boot_panic(biosmem_panic_setup_msg);

    biosmem_heap_start = max_heap_start;
    biosmem_heap_free = max_heap_start;
    biosmem_heap_end = max_heap_end;
}

static uint32_t __boot
biosmem_strlen(uint32_t addr)
{
    const char *s;
    uint32_t i;

    s = (void *)(unsigned long)addr;
    i = 0;

    while (*s++ != '\0')
        i++;

    return i;
}

static void __boot
biosmem_save_cmdline_sizes(struct multiboot_raw_info *mbi)
{
    struct multiboot_raw_module *mod;
    uint32_t i;

    if (mbi->flags & MULTIBOOT_LOADER_CMDLINE)
        mbi->unused0 = biosmem_strlen(mbi->cmdline) + 1;

    if (mbi->flags & MULTIBOOT_LOADER_MODULES) {
        unsigned long addr;

        addr = mbi->mods_addr;

        for (i = 0; i < mbi->mods_count; i++) {
            mod = (struct multiboot_raw_module *)addr + i;
            mod->reserved = biosmem_strlen(mod->string) + 1;
        }
    }
}

void __boot
biosmem_bootstrap(struct multiboot_raw_info *mbi)
{
    if (mbi->flags & MULTIBOOT_LOADER_MMAP)
        biosmem_map_build(mbi);
    else
        biosmem_map_build_simple(mbi);

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
    unsigned long free, page;
    char *ptr;

    if (nr_pages == 0)
        boot_panic(biosmem_panic_inval_msg);

    free = biosmem_heap_free;
    page = free;
    free += PAGE_SIZE * nr_pages;

    if ((free <= biosmem_heap_start) || (free > biosmem_heap_end))
        boot_panic(biosmem_panic_nomem_msg);

    biosmem_heap_free = free;

    for (ptr = (char *)page; ptr < (char *)free; ptr++)
        *ptr = '\0';

    return (void *)page;
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

static int __init
biosmem_map_entry_is_invalid(const struct biosmem_map_entry *entry) {
    return (entry->base_addr + entry->length) <= entry->base_addr;
}

static void __init
biosmem_map_filter(void)
{
    struct biosmem_map_entry *entry;
    unsigned int i;

    i = 0;

    while (i < biosmem_map_size) {
        entry = &biosmem_map[i];

        if (biosmem_map_entry_is_invalid(entry)) {
            biosmem_map_size--;
            memmove(entry, entry + 1, (biosmem_map_size - i) * sizeof(*entry));
            continue;
        }

        i++;
    }
}

static void __init
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

static void __init
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
                    panic("biosmem: too many memory map entries");

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
}

static int __init
biosmem_map_find_avail(phys_addr_t *phys_start, phys_addr_t *phys_end)
{
    const struct biosmem_map_entry *entry, *map_end;
    phys_addr_t start, end, seg_start, seg_end;
    uint64_t entry_end;

    seg_start = (phys_addr_t)-1;
    seg_end = (phys_addr_t)-1;
    map_end = biosmem_map + biosmem_map_size;

    for (entry = biosmem_map; entry < map_end; entry++) {
        if (entry->type != BIOSMEM_TYPE_AVAILABLE)
            continue;

#ifndef VM_PAGE_HIGHMEM_LIMIT
        if (entry->base_addr >= VM_PAGE_NORMAL_LIMIT)
            break;
#endif /* VM_PAGE_HIGHMEM_LIMIT */

        start = vm_page_round(entry->base_addr);

        if (start >= *phys_end)
            break;

        entry_end = entry->base_addr + entry->length;

#ifndef VM_PAGE_HIGHMEM_LIMIT
        if (entry_end > VM_PAGE_NORMAL_LIMIT)
            entry_end = VM_PAGE_NORMAL_LIMIT;
#endif /* VM_PAGE_HIGHMEM_LIMIT */

        end = vm_page_trunc(entry_end);

        /* TODO: check against a minimum size */
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

static void __init
biosmem_load_segment(const char *name, unsigned long long max_phys_end,
                     phys_addr_t phys_start, phys_addr_t phys_end,
                     phys_addr_t avail_start, phys_addr_t avail_end,
                     unsigned int seg_index, unsigned int seglist_prio)
{
    if (phys_end > max_phys_end) {
        if (max_phys_end <= phys_start) {
            printk("biosmem: warning: segment %s physically unreachable, "
                   "not loaded\n", name);
            return;
        }

        printk("biosmem: warning: segment %s truncated to %#llx\n", name,
               max_phys_end);
        phys_end = max_phys_end;
    }

    if ((avail_start < phys_start) || (avail_start > phys_end))
        avail_start = phys_start;

    if ((avail_end < phys_start) || (avail_end > phys_end))
        avail_end = phys_end;

    vm_page_load(name, phys_start, phys_end, avail_start, avail_end,
                 seg_index, seglist_prio);
}

void __init
biosmem_setup(void)
{
    unsigned long long max_phys_end;
    phys_addr_t phys_start, phys_end;
    struct cpu *cpu;
    int error;

    biosmem_map_adjust();
    biosmem_map_show();

    cpu = cpu_current();
    max_phys_end = (cpu->phys_addr_width == 0)
                   ? (unsigned long long)-1
                   : 1ULL << cpu->phys_addr_width;

    phys_start = BIOSMEM_BASE;
    phys_end = VM_PAGE_NORMAL_LIMIT;
    error = biosmem_map_find_avail(&phys_start, &phys_end);

    if (!error)
        biosmem_load_segment("normal", max_phys_end, phys_start, phys_end,
                             biosmem_heap_free, biosmem_heap_end,
                             VM_PAGE_SEG_NORMAL, VM_PAGE_SEGLIST_NORMAL);

#ifdef VM_PAGE_HIGHMEM_LIMIT
    phys_start = VM_PAGE_NORMAL_LIMIT;
    phys_end = VM_PAGE_HIGHMEM_LIMIT;
    error = biosmem_map_find_avail(&phys_start, &phys_end);

    if (!error)
        biosmem_load_segment("highmem", max_phys_end, phys_start, phys_end,
                             phys_start, phys_end,
                             VM_PAGE_SEG_HIGHMEM, VM_PAGE_SEGLIST_HIGHMEM);
#endif /* VM_PAGE_HIGHMEM_LIMIT */
}

static void __init
biosmem_find_reserved_area_update(phys_addr_t min, phys_addr_t *start,
                                  phys_addr_t *end, phys_addr_t reserved_start,
                                  phys_addr_t reserved_end)
{
    if ((min <= reserved_start) && (reserved_start < *start)) {
        *start = reserved_start;
        *end = reserved_end;
    }
}

static phys_addr_t __init
biosmem_find_reserved_area(phys_addr_t min, phys_addr_t max,
                           phys_addr_t *endp)
{
    phys_addr_t start, end = end;

    start = max;
    biosmem_find_reserved_area_update(min, &start, &end, (unsigned long)&_boot,
                                      BOOT_VTOP((unsigned long)&_end));
    biosmem_find_reserved_area_update(min, &start, &end, biosmem_heap_start,
                                      biosmem_heap_end);

    if (start == max)
        return 0;

    *endp = end;
    return start;
}

static void __init
biosmem_free_usable_range(phys_addr_t start, phys_addr_t end)
{
    struct vm_page *page;

    while (start < end) {
        page = vm_page_lookup(start);
        assert(page != NULL);
        vm_page_manage(page);
        start += PAGE_SIZE;
    }
}

static void __init
biosmem_free_usable_upper(phys_addr_t upper_end)
{
    phys_addr_t next, start, end;

    next = BIOSMEM_END;

    do {
        start = next;
        end = biosmem_find_reserved_area(start, upper_end, &next);

        if (end == 0) {
            end = upper_end;
            next = 0;
        }

        biosmem_free_usable_range(start, end);
    } while (next != 0);
}

void __init
biosmem_free_usable(void)
{
    struct biosmem_map_entry *entry;
    phys_addr_t start, end;
    uint64_t entry_end;
    unsigned int i;

    for (i = 0; i < biosmem_map_size; i++) {
        entry = &biosmem_map[i];

        if (entry->type != BIOSMEM_TYPE_AVAILABLE)
            continue;

        /* High memory is always loaded during setup */
        if (entry->base_addr >= VM_PAGE_NORMAL_LIMIT)
            break;

        entry_end = entry->base_addr + entry->length;

        if (entry_end > VM_PAGE_NORMAL_LIMIT)
            entry_end = VM_PAGE_NORMAL_LIMIT;

        start = vm_page_round(entry->base_addr);
        end = vm_page_trunc(entry_end);

        if (start < BIOSMEM_BASE) {
            assert(end < BIOSMEM_END);
            start = BIOSMEM_BASE;
        }

        /*
         * Upper memory contains the kernel and the bootstrap heap, and
         * requires special handling.
         */
        if (start == BIOSMEM_END)
            biosmem_free_usable_upper(end);
        else
            biosmem_free_usable_range(start, end);
    }
}
