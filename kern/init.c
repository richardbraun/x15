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
 * The main purpose of the init module is to provide a convenient interface
 * to declare initialization operations and their dependency, infer an order
 * of execution based on the resulting graph (which must be acyclic), and
 * run the operations in that order. Topological sorting is achieved using
 * Kahn's algorithm.
 */

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <kern/error.h>
#include <kern/init.h>
#include <kern/slist.h>
#include <kern/macros.h>
#include <machine/cpu.h>

#define INIT_DEBUG 1

extern struct init_op _init_ops;
extern struct init_op _init_ops_end;

static_assert(sizeof(struct init_op) == INIT_OP_ALIGN, "invalid init_op size");

/*
 * List of initialization operations.
 *
 * This type is used for the output of the topological sort.
 */
struct init_ops_list {
    struct slist ops;
    size_t size;
};

static void __init
init_ops_list_init(struct init_ops_list *list)
{
    slist_init(&list->ops);
    list->size = 0;
}

static size_t __init
init_ops_list_size(const struct init_ops_list *list)
{
    return list->size;
}

static void __init
init_ops_list_push(struct init_ops_list *list, struct init_op *op)
{
    slist_insert_head(&list->ops, &op->list_node);
    list->size++;
}

static struct init_op * __init
init_ops_list_pop(struct init_ops_list *list)
{
    struct init_op *op;

    if (list->size == 0) {
        return NULL;
    }

    op = slist_first_entry(&list->ops, struct init_op, list_node);
    slist_remove(&list->ops, NULL);
    list->size--;
    return op;
}

/*
 * Stack of initialization operations.
 *
 * This type is used internally by the topological sort algorithm.
 */
struct init_ops_stack {
    struct slist ops;
};

static void __init
init_ops_stack_init(struct init_ops_stack *stack)
{
    slist_init(&stack->ops);
}

static void __init
init_ops_stack_push(struct init_ops_stack *stack, struct init_op *op)
{
    slist_insert_head(&stack->ops, &op->stack_node);
}

static struct init_op * __init
init_ops_stack_pop(struct init_ops_stack *stack)
{
    struct init_op *op;

    if (slist_empty(&stack->ops)) {
        return NULL;
    }

    op = slist_first_entry(&stack->ops, struct init_op, stack_node);
    slist_remove(&stack->ops, NULL);
    return op;
}

static struct init_op_dep * __init
init_op_get_dep(const struct init_op *op, size_t index)
{
    assert(index < op->nr_deps);
    return &op->deps[index];
}

static void __init
init_op_init(struct init_op *op)
{
    struct init_op_dep *dep;

    for (size_t i = 0; i < op->nr_deps; i++) {
        dep = init_op_get_dep(op, i);
        dep->op->nr_parents++;
        assert(dep->op->nr_parents != 0);
    }
}

static bool __init
init_op_orphan(const struct init_op *op)
{
    return (op->nr_parents == 0);
}

static bool __init
init_op_pending(const struct init_op *op)
{
    return op->state == INIT_OP_STATE_PENDING;
}

static void __init
init_op_set_pending(struct init_op *op)
{
    assert(op->state == INIT_OP_STATE_UNLINKED);
    op->state = INIT_OP_STATE_PENDING;
}

static bool __init
init_op_complete(const struct init_op *op)
{
    return op->state == INIT_OP_STATE_COMPLETE;
}

static void __init
init_op_set_complete(struct init_op *op)
{
    assert(init_op_pending(op));
    op->state = INIT_OP_STATE_COMPLETE;
}

static bool __init
init_op_ready(const struct init_op *op)
{
    const struct init_op_dep *dep;
    size_t i;

    for (i = 0; i < op->nr_deps; i++) {
        dep = init_op_get_dep(op, i);

        if (!init_op_complete(dep->op)
            || (dep->required && dep->op->error)) {
            return false;
        }
    }

    return true;
}

static void __init
init_op_run(struct init_op *op)
{
    if (init_op_ready(op)) {
        op->error = op->fn();
    }

    init_op_set_complete(op);
}

#if INIT_DEBUG

#define INIT_DEBUG_LOG_BUFFER_SIZE 8192

struct init_debug_log {
    char buffer[INIT_DEBUG_LOG_BUFFER_SIZE];
    size_t index;
};

/*
 * Buffers used to store an easy-to-dump text representation of init operations.
 *
 * These buffers are meant to be retrieved through a debugging interface such
 * as JTAG.
 */
struct init_debug_logs {
    struct init_debug_log roots;    /* graph roots */
    struct init_debug_log cycles;   /* operations with dependency cycles */
    struct init_debug_log pending;  /* operations successfully sorted */
    struct init_debug_log complete; /* executed operations */
};

static struct init_debug_logs init_debug_logs;

static void __init
init_debug_log_append(struct init_debug_log *log, const char *name)
{
    size_t size;

    if (log->index == sizeof(log->buffer)) {
        return;
    }

    size = sizeof(log->buffer) - log->index;
    log->index += snprintf(log->buffer + log->index, size, "%s ", name);

    if (log->index >= sizeof(log->buffer)) {
        log->index = sizeof(log->buffer);
    }
}

static void __init
init_debug_append_root(const struct init_op *op)
{
    init_debug_log_append(&init_debug_logs.roots, op->name);
}

static void __init
init_debug_append_cycle(const struct init_op *op)
{
    init_debug_log_append(&init_debug_logs.cycles, op->name);
}

static void __init
init_debug_append_pending(const struct init_op *op)
{
    init_debug_log_append(&init_debug_logs.pending, op->name);
}

static void __init
init_debug_append_complete(const struct init_op *op)
{
    init_debug_log_append(&init_debug_logs.complete, op->name);
}

static void __init
init_debug_scan_not_pending(void)
{
    const struct init_op *op;

    for (op = &_init_ops; op < &_init_ops_end; op++) {
        if (!init_op_pending(op)) {
            init_debug_append_cycle(op);
        }
    }
}

#else /* INIT_DEBUG */
#define init_debug_append_root(roots)
#define init_debug_append_pending(op)
#define init_debug_append_complete(op)
#define init_debug_scan_not_pending()
#endif /* INIT_DEBUG */

static void __init
init_add_pending_op(struct init_ops_list *pending_ops, struct init_op *op)
{
    assert(!init_op_pending(op));

    init_op_set_pending(op);
    init_ops_list_push(pending_ops, op);
    init_debug_append_pending(op);
}

static void __init
init_op_visit(struct init_op *op, struct init_ops_stack *stack)
{
    struct init_op_dep *dep;

    for (size_t i = 0; i < op->nr_deps; i++) {
        dep = init_op_get_dep(op, i);
        assert(dep->op->nr_parents != 0);
        dep->op->nr_parents--;

        if (init_op_orphan(dep->op)) {
            init_ops_stack_push(stack, dep->op);
        }
    }
}

static void __init
init_check_ops_alignment(void)
{
    uintptr_t start, end;

    start = (uintptr_t)&_init_ops;
    end = (uintptr_t)&_init_ops_end;

    if (((end - start) % INIT_OP_ALIGN) != 0) {
        cpu_halt();
    }
}

static void __init
init_bootstrap(void)
{
    struct init_op *op;

    init_check_ops_alignment();

    for (op = &_init_ops; op < &_init_ops_end; op++) {
        init_op_init(op);
    }
}

static void __init
init_scan_roots(struct init_ops_stack *stack)
{
    struct init_op *op;

    init_ops_stack_init(stack);

    for (op = &_init_ops; op < &_init_ops_end; op++) {
        if (init_op_orphan(op)) {
            init_ops_stack_push(stack, op);
            init_debug_append_root(op);
        }
    }
}

static void __init
init_scan_ops(struct init_ops_list *pending_ops)
{
    struct init_ops_stack stack;
    struct init_op *op;
    size_t nr_ops;

    init_scan_roots(&stack);

    for (;;) {
        op = init_ops_stack_pop(&stack);

        if (op == NULL) {
            break;
        }

        init_add_pending_op(pending_ops, op);
        init_op_visit(op, &stack);
    }

    init_debug_scan_not_pending();

    nr_ops = &_init_ops_end - &_init_ops;

    if (init_ops_list_size(pending_ops) != nr_ops) {
        cpu_halt();
    }
}

static void __init
init_run_ops(struct init_ops_list *pending_ops)
{
    struct init_op *op;

    for (;;) {
        op = init_ops_list_pop(pending_ops);

        if (op == NULL) {
            break;
        }

        init_op_run(op);
        init_debug_append_complete(op);
    }
}

void __init
init_setup(void)
{
    struct init_ops_list pending_ops;

    init_ops_list_init(&pending_ops);

    init_bootstrap();
    init_scan_ops(&pending_ops);
    init_run_ops(&pending_ops);
}
