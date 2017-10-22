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
 *
 *
 * TODO Define "page table".
 * TODO Review locking.
 */

#include <assert.h>
#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <kern/bootmem.h>
#include <kern/cpumap.h>
#include <kern/error.h>
#include <kern/init.h>
#include <kern/kmem.h>
#include <kern/list.h>
#include <kern/log.h>
#include <kern/macros.h>
#include <kern/mutex.h>
#include <kern/panic.h>
#include <kern/percpu.h>
#include <kern/spinlock.h>
#include <kern/syscnt.h>
#include <kern/thread.h>
#include <machine/boot.h>
#include <machine/cpu.h>
#include <machine/page.h>
#include <machine/pmap.h>
#include <machine/tcb.h>
#include <machine/trap.h>
#include <machine/types.h>
#include <vm/vm_kmem.h>
#include <vm/vm_page.h>
#include <vm/vm_ptable.h>
#include <vm/vm_prot.h>

static const struct vm_ptable_level *vm_ptable_boot_pt_levels __bootdata;
static unsigned int vm_ptable_boot_nr_levels __bootdata;

static struct vm_ptable_cpu_pt vm_ptable_boot_cpu_pt __bootdata;

/*
 * Structures related to inter-processor page table updates.
 */

#define VM_PTABLE_UPDATE_OP_ENTER       1
#define VM_PTABLE_UPDATE_OP_REMOVE      2
#define VM_PTABLE_UPDATE_OP_PROTECT     3

struct vm_ptable_update_enter_args {
    uintptr_t va;
    phys_addr_t pa;
    int prot;
    int flags;
};

struct vm_ptable_update_remove_args {
    uintptr_t start;
    uintptr_t end;
};

struct vm_ptable_update_protect_args {
    uintptr_t start;
    uintptr_t end;
    int prot;
};

struct vm_ptable_update_op {
    struct cpumap cpumap;
    unsigned int operation;

    union {
        struct vm_ptable_update_enter_args enter_args;
        struct vm_ptable_update_remove_args remove_args;
        struct vm_ptable_update_protect_args protect_args;
    };
};

/*
 * Maximum number of operations that can be batched before an implicit
 * update.
 */
#define VM_PTABLE_UPDATE_MAX_OPS 32

/*
 * List of update operations.
 *
 * A list of update operations is a container of operations that are pending
 * for a pmap. Updating can be implicit, e.g. when a list has reached its
 * maximum size, or explicit, when vm_ptable_update() is called. Operation lists
 * are thread-local objects.
 *
 * The cpumap is the union of all processors affected by at least one
 * operation.
 */
struct vm_ptable_update_oplist {
    alignas(CPU_L1_SIZE) struct cpumap cpumap;
    struct pmap *pmap;
    unsigned int nr_ops;
    struct vm_ptable_update_op ops[VM_PTABLE_UPDATE_MAX_OPS];
};

/*
 * Statically allocated data for the main booter thread.
 */
static struct vm_ptable_update_oplist vm_ptable_booter_oplist __initdata;

/*
 * Each regular thread gets an operation list from this cache.
 */
static struct kmem_cache vm_ptable_update_oplist_cache;

/*
 * Queue holding update requests from remote processors.
 */
struct vm_ptable_update_queue {
    struct spinlock lock;
    struct list requests;
};

/*
 * Syncer thread.
 *
 * There is one such thread per processor. They are the recipients of
 * update requests, providing thread context for the mapping operations
 * they perform.
 */
struct vm_ptable_syncer {
    alignas(CPU_L1_SIZE) struct thread *thread;
    struct vm_ptable_update_queue queue;
    struct syscnt sc_updates;
    struct syscnt sc_update_enters;
    struct syscnt sc_update_removes;
    struct syscnt sc_update_protects;
};

#if 0
static void vm_ptable_sync(void *arg);
#endif

static struct vm_ptable_syncer vm_ptable_syncer __percpu;

/*
 * Maximum number of mappings for which individual TLB invalidations can be
 * performed. Global TLB flushes are done beyond this value.
 */
#define VM_PTABLE_UPDATE_MAX_MAPPINGS 64

/*
 * Per processor request, queued on a remote processor.
 *
 * The number of mappings is used to determine whether it's best to flush
 * individual TLB entries or globally flush the TLB.
 */
struct vm_ptable_update_request {
    alignas(CPU_L1_SIZE) struct list node;
    struct spinlock lock;
    struct thread *sender;
    const struct vm_ptable_update_oplist *oplist;
    unsigned int nr_mappings;
    int done;
    int error;
};

/*
 * Per processor array of requests.
 *
 * When an operation list is to be applied, the thread triggering the update
 * acquires the processor-local array of requests and uses it to queue requests
 * on remote processors.
 */
struct vm_ptable_update_request_array {
    struct vm_ptable_update_request requests[CONFIG_MAX_CPUS];
    struct mutex lock;
};

static struct vm_ptable_update_request_array vm_ptable_update_request_array
    __percpu;

static int vm_ptable_do_remote_updates __read_mostly;

static char vm_ptable_panic_inval_msg[] __bootdata
    = "vm_ptable: invalid physical address";

void __boot
vm_ptable_bootstrap(const struct vm_ptable_level *pt_levels,
                    unsigned int nr_levels)
{
    assert(pt_levels);
    assert(nr_levels != 0);

    vm_ptable_boot_pt_levels = pt_levels;
    vm_ptable_boot_nr_levels = nr_levels;
}

static const struct vm_ptable_level * __boot
vm_ptable_boot_get_pt_level(unsigned int level)
{
    assert(level < vm_ptable_boot_nr_levels);
    return &vm_ptable_boot_pt_levels[level];
}

static __always_inline unsigned long
vm_ptable_level_pte_index(const struct vm_ptable_level *pt_level, uintptr_t va)
{
    return ((va >> pt_level->skip) & ((1UL << pt_level->bits) - 1));
}

static __always_inline phys_addr_t
vm_ptable_level_pa_mask(const struct vm_ptable_level *pt_level)
{
    phys_addr_t size;

    if (pt_level == vm_ptable_boot_pt_levels) {
        return ~PAGE_MASK;
    } else {
        pt_level--;
        size = ((phys_addr_t)1 << pt_level->bits) * sizeof(pmap_pte_t);
        return ~(size - 1);
    }
}

static __always_inline bool
vm_ptable_pa_aligned(phys_addr_t pa)
{
    phys_addr_t mask;

    mask = vm_ptable_level_pa_mask(vm_ptable_boot_get_pt_level(0));
    return pa == (pa & mask);
}

void __boot
vm_ptable_build(struct vm_ptable *ptable)
{
    const struct vm_ptable_level *pt_level;
    struct vm_ptable_cpu_pt *pt;

    pt_level = vm_ptable_boot_get_pt_level(vm_ptable_boot_nr_levels - 1);
    pt = &vm_ptable_boot_cpu_pt;
    pt->root = bootmem_alloc(pt_level->ptes_per_pt * sizeof(pmap_pte_t));
    ptable->cpu_pts[0] = pt;

    for (size_t i = 1; i < ARRAY_SIZE(ptable->cpu_pts); i++) {
        ptable->cpu_pts[i] = NULL;
    }
}

void __boot
vm_ptable_boot_enter(struct vm_ptable *ptable, uintptr_t va,
                     phys_addr_t pa, size_t pgsize)
{
    const struct vm_ptable_level *pt_level;
    unsigned int level, last_level;
    pmap_pte_t *pt, *next_pt, *pte;
    phys_addr_t mask;

    if (!vm_ptable_pa_aligned(pa)) {
        boot_panic(vm_ptable_panic_inval_msg);
    }

#if 0
    switch (pgsize) {
    case (1 << PMAP_L1_SKIP):
        last_level = 1;
        break;
    default:
#endif
    last_level = 0;
    pt = ptable->cpu_pts[0]->root;

    for (level = vm_ptable_boot_nr_levels - 1; level != last_level; level--) {
        pt_level = vm_ptable_boot_get_pt_level(level);
        pte = &pt[vm_ptable_level_pte_index(pt_level, va)];

        if (pmap_pte_valid(*pte)) {
            mask = vm_ptable_level_pa_mask(pt_level);
            next_pt = (void *)(uintptr_t)(*pte & mask);
        } else {
            next_pt = bootmem_alloc(pt_level->ptes_per_pt * sizeof(pmap_pte_t));
            *pte = pt_level->make_pte_fn((uintptr_t)next_pt, VM_PROT_ALL);
        }

        pt = next_pt;
    }

    pt_level = vm_ptable_boot_get_pt_level(last_level);
    pte = &pt[vm_ptable_level_pte_index(pt_level, va)];
    *pte = pt_level->make_ll_pte_fn(pa, VM_PROT_ALL);
}

pmap_pte_t * __boot
vm_ptable_boot_root(const struct vm_ptable *ptable)
{
    return ptable->cpu_pts[0]->root;
}
