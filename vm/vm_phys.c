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
 *
 *
 * This implementation uses the binary buddy system to manage its heap.
 * Descriptions of the buddy system can be found in the following works :
 * - "UNIX Internals: The New Frontiers", by Uresh Vahalia.
 * - "Dynamic Storage Allocation: A Survey and Critical Review",
 *    by Paul R. Wilson, Mark S. Johnstone, Michael Neely, and David Boles.
 *
 * In addition, this allocator uses per-CPU pools of pages for order 0
 * (i.e. single page) allocations. These pools act as caches (but are named
 * differently to avoid confusion with CPU caches) that reduce contention on
 * multiprocessor systems. When a pool is empty and cannot provide a page,
 * it is filled by transferring multiple pages from the backend buddy system.
 * The symmetric case is handled likewise.
 */

#include <kern/assert.h>
#include <kern/init.h>
#include <kern/list.h>
#include <kern/macros.h>
#include <kern/panic.h>
#include <kern/param.h>
#include <kern/printk.h>
#include <kern/spinlock.h>
#include <kern/sprintf.h>
#include <kern/stddef.h>
#include <kern/string.h>
#include <kern/types.h>
#include <machine/cpu.h>
#include <vm/vm_kmem.h>
#include <vm/vm_page.h>
#include <vm/vm_phys.h>

/*
 * Number of free block lists per segment.
 */
#define VM_PHYS_NR_FREE_LISTS 11

/*
 * The size of a CPU pool is computed by dividing the number of pages in its
 * containing segment by this value.
 */
#define VM_PHYS_CPU_POOL_RATIO 1024

/*
 * Maximum number of pages in a CPU pool.
 */
#define VM_PHYS_CPU_POOL_MAX_SIZE 128

/*
 * The transfer size of a CPU pool is computed by dividing the pool size by
 * this value.
 */
#define VM_PHYS_CPU_POOL_TRANSFER_RATIO 2

/*
 * Per-processor cache of pages.
 */
struct vm_phys_cpu_pool {
    struct spinlock lock;
    int size;
    int transfer_size;
    int nr_pages;
    struct list pages;
};

/*
 * Special order value.
 *
 * When a page is free, its order is the index of its free list.
 */
#define VM_PHYS_ORDER_ALLOCATED VM_PHYS_NR_FREE_LISTS

/*
 * Doubly-linked list of free blocks.
 */
struct vm_phys_free_list {
    unsigned long size;
    struct list blocks;
};

/*
 * Segment name buffer size.
 */
#define VM_PHYS_NAME_SIZE 16

/*
 * Segment of contiguous memory.
 */
struct vm_phys_seg {
    struct vm_phys_cpu_pool cpu_pools[MAX_CPUS];

    struct list node;
    phys_addr_t start;
    phys_addr_t end;
    struct vm_page *pages;
    struct vm_page *pages_end;
    struct spinlock lock;
    struct vm_phys_free_list free_lists[VM_PHYS_NR_FREE_LISTS];
    unsigned long nr_free_pages;
    char name[VM_PHYS_NAME_SIZE];
};

/*
 * Bootstrap information about a segment.
 */
struct vm_phys_boot_seg {
    phys_addr_t avail_start;
    phys_addr_t avail_end;
};

int vm_phys_ready;

/*
 * Segment lists, ordered by priority.
 */
static struct list vm_phys_seg_lists[VM_NR_PHYS_SEGLIST];

/*
 * Segment table.
 */
static struct vm_phys_seg vm_phys_segs[VM_MAX_PHYS_SEG];

/*
 * Bootstrap segment table.
 */
static struct vm_phys_boot_seg vm_phys_boot_segs[VM_MAX_PHYS_SEG] __initdata;

/*
 * Number of loaded segments.
 */
static unsigned int vm_phys_segs_size;

static int vm_phys_load_initialized __initdata = 0;

static void __init
vm_phys_init_page(struct vm_page *page, unsigned short seg_index,
                  unsigned short order, phys_addr_t pa)
{
    page->seg_index = seg_index;
    page->order = order;
    page->phys_addr = pa;
    page->slab_priv = NULL;
}

static void __init
vm_phys_free_list_init(struct vm_phys_free_list *free_list)
{
    free_list->size = 0;
    list_init(&free_list->blocks);
}

static inline void
vm_phys_free_list_insert(struct vm_phys_free_list *free_list,
                         struct vm_page *page)
{
    assert(page->order == VM_PHYS_ORDER_ALLOCATED);

    free_list->size++;
    list_insert(&free_list->blocks, &page->node);
}

static inline void
vm_phys_free_list_remove(struct vm_phys_free_list *free_list,
                         struct vm_page *page)
{
    assert(free_list->size != 0);
    assert(!list_empty(&free_list->blocks));
    assert(page->order < VM_PHYS_NR_FREE_LISTS);

    free_list->size--;
    list_remove(&page->node);
}

static struct vm_page *
vm_phys_seg_alloc_from_buddy(struct vm_phys_seg *seg, unsigned int order)
{
    struct vm_phys_free_list *free_list;
    struct vm_page *page, *buddy;
    unsigned int i;

    assert(order < VM_PHYS_NR_FREE_LISTS);

    for (i = order; i < VM_PHYS_NR_FREE_LISTS; i++) {
        free_list = &seg->free_lists[i];

        if (free_list->size != 0)
            break;
    }

    if (i == VM_PHYS_NR_FREE_LISTS)
        return NULL;

    page = list_first_entry(&free_list->blocks, struct vm_page, node);
    vm_phys_free_list_remove(free_list, page);
    page->order = VM_PHYS_ORDER_ALLOCATED;

    while (i > order) {
        i--;
        buddy = &page[1 << i];
        vm_phys_free_list_insert(&seg->free_lists[i], buddy);
        buddy->order = i;
    }

    seg->nr_free_pages -= (1 << order);
    return page;
}

static void
vm_phys_seg_free_to_buddy(struct vm_phys_seg *seg, struct vm_page *page,
                          unsigned int order)
{
    struct vm_page *buddy;
    phys_addr_t pa, buddy_pa;
    unsigned int nr_pages;

    assert(page >= seg->pages);
    assert(page < seg->pages_end);
    assert(page->order == VM_PHYS_ORDER_ALLOCATED);
    assert(order < VM_PHYS_NR_FREE_LISTS);

    nr_pages = (1 << order);
    pa = page->phys_addr;

    while (order < (VM_PHYS_NR_FREE_LISTS - 1)) {
        buddy_pa = pa ^ vm_page_ptoa(1 << order);

        if ((buddy_pa < seg->start) || (buddy_pa >= seg->end))
            break;

        buddy = &seg->pages[vm_page_atop(buddy_pa - seg->start)];

        if (buddy->order != order)
            break;

        vm_phys_free_list_remove(&seg->free_lists[order], buddy);
        buddy->order = VM_PHYS_ORDER_ALLOCATED;
        order++;
        pa &= -vm_page_ptoa(1 << order);
        page = &seg->pages[vm_page_atop(pa - seg->start)];
    }

    vm_phys_free_list_insert(&seg->free_lists[order], page);
    page->order = order;
    seg->nr_free_pages += nr_pages;
}

static void __init
vm_phys_cpu_pool_init(struct vm_phys_cpu_pool *cpu_pool, int size)
{
    spinlock_init(&cpu_pool->lock);
    cpu_pool->size = size;
    cpu_pool->transfer_size = (size + VM_PHYS_CPU_POOL_TRANSFER_RATIO - 1)
                              / VM_PHYS_CPU_POOL_TRANSFER_RATIO;
    cpu_pool->nr_pages = 0;
    list_init(&cpu_pool->pages);
}

static inline struct vm_phys_cpu_pool *
vm_phys_cpu_pool_get(struct vm_phys_seg *seg)
{
    return &seg->cpu_pools[cpu_id()];
}

static inline struct vm_page *
vm_phys_cpu_pool_pop(struct vm_phys_cpu_pool *cpu_pool)
{
    struct vm_page *page;

    assert(cpu_pool->nr_pages != 0);
    cpu_pool->nr_pages--;
    page = list_first_entry(&cpu_pool->pages, struct vm_page, node);
    list_remove(&page->node);
    return page;
}

static inline void
vm_phys_cpu_pool_push(struct vm_phys_cpu_pool *cpu_pool, struct vm_page *page)
{
    assert(cpu_pool->nr_pages < cpu_pool->size);
    cpu_pool->nr_pages++;
    list_insert(&cpu_pool->pages, &page->node);
}

static int
vm_phys_cpu_pool_fill(struct vm_phys_cpu_pool *cpu_pool,
                      struct vm_phys_seg *seg)
{
    struct vm_page *page;
    int i;

    assert(cpu_pool->nr_pages == 0);

    spinlock_lock(&seg->lock);

    for (i = 0; i < cpu_pool->transfer_size; i++) {
        page = vm_phys_seg_alloc_from_buddy(seg, 0);

        if (page == NULL)
            break;

        vm_phys_cpu_pool_push(cpu_pool, page);
    }

    spinlock_unlock(&seg->lock);

    return i;
}

static void
vm_phys_cpu_pool_drain(struct vm_phys_cpu_pool *cpu_pool,
                       struct vm_phys_seg *seg)
{
    struct vm_page *page;
    int i;

    assert(cpu_pool->nr_pages == cpu_pool->size);

    spinlock_lock(&seg->lock);

    for (i = cpu_pool->transfer_size; i > 0; i--) {
        page = vm_phys_cpu_pool_pop(cpu_pool);
        vm_phys_seg_free_to_buddy(seg, page, 0);
    }

    spinlock_unlock(&seg->lock);
}

static inline phys_addr_t __init
vm_phys_seg_size(struct vm_phys_seg *seg)
{
    return seg->end - seg->start;
}

static int __init
vm_phys_seg_compute_pool_size(struct vm_phys_seg *seg)
{
    phys_addr_t size;

    size = vm_page_atop(vm_phys_seg_size(seg)) / VM_PHYS_CPU_POOL_RATIO;

    if (size == 0)
        size = 1;
    else if (size > VM_PHYS_CPU_POOL_MAX_SIZE)
        size = VM_PHYS_CPU_POOL_MAX_SIZE;

    return size;
}

static void __init
vm_phys_seg_init(struct vm_phys_seg *seg, struct vm_page *pages)
{
    phys_addr_t pa;
    int pool_size;
    unsigned int i;

    pool_size = vm_phys_seg_compute_pool_size(seg);

    for (i = 0; i < ARRAY_SIZE(seg->cpu_pools); i++)
        vm_phys_cpu_pool_init(&seg->cpu_pools[i], pool_size);

    seg->pages = pages;
    seg->pages_end = pages + vm_page_atop(vm_phys_seg_size(seg));
    spinlock_init(&seg->lock);

    for (i = 0; i < ARRAY_SIZE(seg->free_lists); i++)
        vm_phys_free_list_init(&seg->free_lists[i]);

    seg->nr_free_pages = 0;
    i = seg - vm_phys_segs;

    for (pa = seg->start; pa < seg->end; pa += PAGE_SIZE)
        vm_phys_init_page(&pages[vm_page_atop(pa - seg->start)], i,
                          VM_PHYS_ORDER_ALLOCATED, pa);
}

static struct vm_page *
vm_phys_seg_alloc(struct vm_phys_seg *seg, unsigned int order)
{
    struct vm_phys_cpu_pool *cpu_pool;
    struct vm_page *page;
    int filled;

    assert(order < VM_PHYS_NR_FREE_LISTS);

    if (order == 0) {
        cpu_pool = vm_phys_cpu_pool_get(seg);

        spinlock_lock(&cpu_pool->lock);

        if (cpu_pool->nr_pages == 0) {
            filled = vm_phys_cpu_pool_fill(cpu_pool, seg);

            if (!filled) {
                spinlock_unlock(&cpu_pool->lock);
                return NULL;
            }
        }

        page = vm_phys_cpu_pool_pop(cpu_pool);
        spinlock_unlock(&cpu_pool->lock);
    } else {
        spinlock_lock(&seg->lock);
        page = vm_phys_seg_alloc_from_buddy(seg, order);
        spinlock_unlock(&seg->lock);
    }

    return page;
}

static void
vm_phys_seg_free(struct vm_phys_seg *seg, struct vm_page *page,
                 unsigned int order)
{
    struct vm_phys_cpu_pool *cpu_pool;

    assert(order < VM_PHYS_NR_FREE_LISTS);

    if (order == 0) {
        cpu_pool = vm_phys_cpu_pool_get(seg);

        spinlock_lock(&cpu_pool->lock);

        if (cpu_pool->nr_pages == cpu_pool->size)
            vm_phys_cpu_pool_drain(cpu_pool, seg);

        vm_phys_cpu_pool_push(cpu_pool, page);
        spinlock_unlock(&cpu_pool->lock);
    } else {
        spinlock_lock(&seg->lock);
        vm_phys_seg_free_to_buddy(seg, page, order);
        spinlock_unlock(&seg->lock);
    }
}

void __init
vm_phys_load(const char *name, phys_addr_t start, phys_addr_t end,
             phys_addr_t avail_start, phys_addr_t avail_end,
             unsigned int seg_index, unsigned int seglist_prio)
{
    struct vm_phys_boot_seg *boot_seg;
    struct vm_phys_seg *seg;
    struct list *seg_list;
    unsigned int i;

    assert(name != NULL);
    assert(start < end);
    assert(seg_index < ARRAY_SIZE(vm_phys_segs));
    assert(seglist_prio < ARRAY_SIZE(vm_phys_seg_lists));

    if (!vm_phys_load_initialized) {
        for (i = 0; i < ARRAY_SIZE(vm_phys_seg_lists); i++)
            list_init(&vm_phys_seg_lists[i]);

        vm_phys_segs_size = 0;
        vm_phys_load_initialized = 1;
    }

    assert(vm_phys_segs_size < ARRAY_SIZE(vm_phys_segs));

    boot_seg = &vm_phys_boot_segs[seg_index];
    seg = &vm_phys_segs[seg_index];
    seg_list = &vm_phys_seg_lists[seglist_prio];

    list_insert_tail(seg_list, &seg->node);
    seg->start = start;
    seg->end = end;
    strlcpy(seg->name, name, sizeof(seg->name));
    boot_seg->avail_start = avail_start;
    boot_seg->avail_end = avail_end;

    vm_phys_segs_size++;
}

phys_addr_t __init
vm_phys_bootalloc(void)
{
    struct vm_phys_boot_seg *boot_seg;
    struct vm_phys_seg *seg;
    struct list *seg_list;
    phys_addr_t pa;

    for (seg_list = &vm_phys_seg_lists[ARRAY_SIZE(vm_phys_seg_lists) - 1];
         seg_list >= vm_phys_seg_lists;
         seg_list--)
        list_for_each_entry(seg_list, seg, node) {
            boot_seg = &vm_phys_boot_segs[seg - vm_phys_segs];

            if ((boot_seg->avail_end - boot_seg->avail_start) > 1) {
                pa = boot_seg->avail_start;
                boot_seg->avail_start += PAGE_SIZE;
                return pa;
            }
        }

    panic("vm_phys: no physical memory available");
}

void __init
vm_phys_setup(void)
{
    struct vm_phys_boot_seg *boot_seg;
    struct vm_phys_seg *seg;
    struct vm_page *map, *start, *end;
    size_t pages, map_size;
    unsigned int i;

    /*
     * Compute the memory map size.
     */
    pages = 0;

    for (i = 0; i < vm_phys_segs_size; i++)
        pages += vm_page_atop(vm_phys_seg_size(&vm_phys_segs[i]));

    map_size = P2ROUND(pages * sizeof(struct vm_page), PAGE_SIZE);
    printk("vm_phys: page table size: %zu entries (%zuk)\n", pages,
           map_size >> 10);
    map = (struct vm_page *)vm_kmem_bootalloc(map_size);

    /*
     * Initialize the segments, associating them to the memory map. When
     * the segments are initialized, all their pages are set allocated,
     * with a block size of one (order 0). They are then released, which
     * populates the free lists.
     */
    for (i = 0; i < vm_phys_segs_size; i++) {
        seg = &vm_phys_segs[i];
        boot_seg = &vm_phys_boot_segs[i];
        vm_phys_seg_init(seg, map);

        start = seg->pages + vm_page_atop(boot_seg->avail_start - seg->start);
        end = seg->pages + vm_page_atop(boot_seg->avail_end - seg->start);

        while (start < end) {
            vm_phys_seg_free_to_buddy(seg, start, 0);
            start++;
        }

        map += vm_page_atop(vm_phys_seg_size(seg));
    }

    vm_phys_ready = 1;
}

void __init
vm_phys_manage(struct vm_page *page)
{
    assert(page->seg_index < ARRAY_SIZE(vm_phys_segs));

    vm_phys_seg_free_to_buddy(&vm_phys_segs[page->seg_index], page, 0);
}

struct vm_page *
vm_phys_lookup_page(phys_addr_t pa)
{
    struct vm_phys_seg *seg;
    unsigned int i;

    for (i = 0; i < vm_phys_segs_size; i++) {
        seg = &vm_phys_segs[i];

        if ((pa >= seg->start) && (pa < seg->end))
            return &seg->pages[vm_page_atop(pa - seg->start)];
    }

    return NULL;
}

struct vm_page *
vm_phys_alloc(unsigned int order)
{
    struct vm_phys_seg *seg;
    struct list *seg_list;
    struct vm_page *page;

    for (seg_list = &vm_phys_seg_lists[ARRAY_SIZE(vm_phys_seg_lists) - 1];
         seg_list >= vm_phys_seg_lists;
         seg_list--)
        list_for_each_entry(seg_list, seg, node) {
            page = vm_phys_seg_alloc(seg, order);

            if (page != NULL)
                return page;
        }

    return NULL;
}

struct vm_page *
vm_phys_alloc_seg(unsigned int order, unsigned int seg_index)
{
    assert(seg_index < vm_phys_segs_size);

    return vm_phys_seg_alloc(&vm_phys_segs[seg_index], order);
}

void
vm_phys_free(struct vm_page *page, unsigned int order)
{
    assert(page->seg_index < ARRAY_SIZE(vm_phys_segs));

    vm_phys_seg_free(&vm_phys_segs[page->seg_index], page, order);
}

void
vm_phys_info(void)
{
    struct vm_phys_seg *seg;
    unsigned long pages;
    unsigned int i;

    for (i = 0; i < vm_phys_segs_size; i++) {
        seg = &vm_phys_segs[i];
        pages = (unsigned long)(seg->pages_end - seg->pages);
        printk("vm_phys: %s: pages: %lu (%luM), free: %lu (%luM)\n", seg->name,
               pages, pages >> (20 - PAGE_SHIFT), seg->nr_free_pages,
               seg->nr_free_pages >> (20 - PAGE_SHIFT));
    }
}
