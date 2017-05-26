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
 *
 *
 * XXX Until more hardware is supported, the model used in this implementation
 * remains a very simple one, where interrupt controllers are global to the
 * system, and each interrupt is targeted at a single processor.
 *
 * Shared interrupts are supported.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include <kern/atomic.h>
#include <kern/kmem.h>
#include <kern/init.h>
#include <kern/intr.h>
#include <kern/list.h>
#include <kern/macros.h>
#include <kern/panic.h>
#include <kern/param.h>
#include <kern/spinlock.h>
#include <kern/thread.h>
#include <machine/cpu.h>

struct intr_handler {
    struct list node;
    intr_handler_fn_t fn;
    void *arg;
} __aligned(CPU_L1_SIZE);

/*
 * Interrupt controller.
 *
 * All members are currently read-only once all controllers have been
 * registered.
 */
struct intr_ctl {
    struct list node;
    const struct intr_ops *ops;
    void *priv;
    unsigned int first_intr;
    unsigned int last_intr;
};

/*
 * Interrupt table entry, one per vector.
 *
 * Interrupts must be disabled when accessing an entry.
 *
 * Each interrupt can be routed to one processor at most. Make each entry
 * span a cache line to avoid false sharing.
 */
struct intr_entry {
    struct spinlock lock;
    struct intr_ctl *ctl;
    unsigned int cpu;
    struct list handlers;
} __aligned(CPU_L1_SIZE);

/*
 * Interrupt table.
 */
static struct intr_entry intr_table[INTR_TABLE_SIZE];

/*
 * List of registered controllers.
 */
static struct list intr_ctls;

static struct kmem_cache intr_handler_cache;

/*
 * Next processor to route interrupts to.
 *
 * TODO Replace the simple current round-robin policy with a better one.
 */
static unsigned int intr_next_cpu;

static unsigned int
intr_select_cpu(void)
{
    return atomic_fetch_add(&intr_next_cpu, 1, ATOMIC_RELAXED) % cpu_count();
}

static int
intr_handler_create(struct intr_handler **handlerp,
                    intr_handler_fn_t fn, void *arg)
{
    struct intr_handler *handler;

    handler = kmem_cache_alloc(&intr_handler_cache);

    if (handler == NULL) {
        return ERROR_NOMEM;
    }

    handler->fn = fn;
    handler->arg = arg;
    *handlerp = handler;
    return 0;
}

static void
intr_handler_destroy(struct intr_handler *handler)
{
    kmem_cache_free(&intr_handler_cache, handler);
}

static bool
intr_handler_match(const struct intr_handler *handler, intr_handler_fn_t fn)
{
    return handler->fn == fn;
}

static int
intr_handler_run(struct intr_handler *handler)
{
    return handler->fn(handler->arg);
}

static struct intr_ctl * __init
intr_ctl_create(const struct intr_ops *ops, void *priv,
                unsigned int first_intr, unsigned int last_intr)
{
    struct intr_ctl *ctl;

    assert(ops != NULL);
    assert(first_intr < last_intr);

    ctl = kmem_alloc(sizeof(*ctl));

    if (ctl == NULL) {
        panic("intr: unable to allocate memory for controller");
    }

    ctl->ops = ops;
    ctl->priv = priv;
    ctl->first_intr = first_intr;
    ctl->last_intr = last_intr;
    return ctl;
}

static bool
intr_ctl_has_intr(const struct intr_ctl *ctl, unsigned int intr)
{
    return ((intr >= ctl->first_intr) && (intr <= ctl->last_intr));
}

static void
intr_ctl_enable(struct intr_ctl *ctl, unsigned int intr, unsigned int cpu)
{
    ctl->ops->enable(ctl->priv, intr, cpu);
}

static void
intr_ctl_disable(struct intr_ctl *ctl, unsigned int intr)
{
    ctl->ops->disable(ctl->priv, intr);
}

static void
intr_ctl_eoi(struct intr_ctl *ctl, unsigned int intr)
{
    ctl->ops->eoi(ctl->priv, intr);
}

static struct intr_ctl *
intr_lookup_ctl(unsigned int intr)
{
    struct intr_ctl *ctl;

    list_for_each_entry(&intr_ctls, ctl, node) {
        if (intr_ctl_has_intr(ctl, intr)) {
            return ctl;
        }
    }

    return NULL;
}

static void __init
intr_entry_init(struct intr_entry *entry)
{
    spinlock_init(&entry->lock);
    list_init(&entry->handlers);
}

static bool
intr_entry_empty(const struct intr_entry *entry)
{
    return list_empty(&entry->handlers);
}

static unsigned int
intr_entry_get_intr(const struct intr_entry *entry)
{
    size_t id;

    id = entry - intr_table;
    assert(id < ARRAY_SIZE(intr_table));
    return id;
}

static void
intr_entry_enable(struct intr_entry *entry, struct intr_ctl *ctl, unsigned int cpu)
{
    entry->ctl = ctl;
    entry->cpu = cpu;
    intr_ctl_enable(entry->ctl, intr_entry_get_intr(entry), cpu);
}

static void
intr_entry_disable(struct intr_entry *entry)
{
    intr_ctl_disable(entry->ctl, intr_entry_get_intr(entry));
}

static struct intr_handler *
intr_entry_lookup_handler(const struct intr_entry *entry, intr_handler_fn_t fn)
{
    struct intr_handler *handler;

    list_for_each_entry(&entry->handlers, handler, node) {
        if (intr_handler_match(handler, fn)) {
            return handler;
        }
    }

    return NULL;
}

static int
intr_entry_add(struct intr_entry *entry, struct intr_handler *handler)
{
    struct intr_ctl *ctl;
    unsigned long flags;
    unsigned int cpu;
    int error;

    spinlock_lock_intr_save(&entry->lock, &flags);

    if (intr_entry_empty(entry)) {
        ctl = intr_lookup_ctl(intr_entry_get_intr(entry));

        if (ctl == NULL) {
            error = ERROR_NODEV;
            goto out;
        }

        cpu = intr_select_cpu();
        intr_entry_enable(entry, ctl, cpu);
    }

    list_insert_tail(&entry->handlers, &handler->node);
    error = 0;

out:
    spinlock_unlock_intr_restore(&entry->lock, flags);

    return error;
}

static struct intr_handler *
intr_entry_remove(struct intr_entry *entry, intr_handler_fn_t fn)
{
    struct intr_handler *handler;
    unsigned long flags;

    spinlock_lock_intr_save(&entry->lock, &flags);

    handler = intr_entry_lookup_handler(entry, fn);

    if (handler == NULL) {
        goto out;
    }

    list_remove(&handler->node);

    if (intr_entry_empty(entry)) {
        intr_entry_disable(entry);
    }

out:
    spinlock_unlock_intr_restore(&entry->lock, flags);

    return handler;
}

static void
intr_entry_eoi(struct intr_entry *entry, unsigned int intr)
{
    assert(entry->ctl != NULL);
    intr_ctl_eoi(entry->ctl, intr);
}

static struct intr_entry *
intr_get_entry(unsigned int intr)
{
    assert(intr < ARRAY_SIZE(intr_table));
    return &intr_table[intr];
}

void __init
intr_setup(void)
{
    unsigned int i;

    list_init(&intr_ctls);
    kmem_cache_init(&intr_handler_cache, "intr_handler",
                    sizeof(struct intr_handler), alignof(struct intr_handler),
                    NULL, 0);

    for (i = 0; i < ARRAY_SIZE(intr_table); i++) {
        intr_entry_init(intr_get_entry(i));
    }
}

static void __init
intr_check_range(unsigned int first_intr, unsigned int last_intr)
{
    struct intr_ctl *ctl;
    unsigned int i;

    list_for_each_entry(&intr_ctls, ctl, node) {
        for (i = first_intr; i <= last_intr; i++) {
            if (intr_ctl_has_intr(ctl, i)) {
                panic("intr: controller range conflict");
            }
        }
    }
}

void __init
intr_register_ctl(const struct intr_ops *ops, void *priv,
                  unsigned int first_intr, unsigned int last_intr)
{
    struct intr_ctl *ctl;

    ctl = intr_ctl_create(ops, priv, first_intr, last_intr);
    intr_check_range(first_intr, last_intr);
    list_insert_tail(&intr_ctls, &ctl->node);
}

int
intr_register(unsigned int intr, intr_handler_fn_t fn, void *arg)
{
    struct intr_handler *handler;
    int error;

    error = intr_handler_create(&handler, fn, arg);

    if (error) {
        return error;
    }

    error = intr_entry_add(intr_get_entry(intr), handler);

    if (error) {
        goto error;
    }

    return 0;

error:
    intr_handler_destroy(handler);
    return error;
}

void
intr_unregister(unsigned int intr, intr_handler_fn_t fn)
{
    struct intr_handler *handler;

    handler = intr_entry_remove(intr_get_entry(intr), fn);

    if (handler == NULL) {
        printf("intr: warning: attempting to unregister unknown handler\n");
        return;
    }

    intr_handler_destroy(handler);
}

void
intr_handle(unsigned int intr)
{
    struct intr_handler *handler;
    struct intr_entry *entry;
    int error;

    assert(!cpu_intr_enabled());
    assert(thread_interrupted());

    entry = intr_get_entry(intr);

    spinlock_lock(&entry->lock);

    intr_entry_eoi(entry, intr);

    list_for_each_entry(&entry->handlers, handler, node) {
        error = intr_handler_run(handler);

        if (!error) {
            break;
        }
    }

    spinlock_unlock(&entry->lock);
}
