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
 */

#ifndef _KERN_INIT_I_H
#define _KERN_INIT_I_H

#include <stdalign.h>
#include <stdbool.h>
#include <stddef.h>

#include <kern/slist_types.h>
#include <kern/macros.h>

#define __initop __section(QUOTE(INIT_OPS_SECTION))

#define INIT_OP_STATE_UNLINKED      0
#define INIT_OP_STATE_PENDING       1
#define INIT_OP_STATE_COMPLETE      2

struct init_op {
    alignas(INIT_OP_ALIGN) struct slist_node list_node;
    struct slist_node stack_node;
    const char *name;
    init_op_fn_t fn;
    struct init_op_dep *deps;
    int error;
    unsigned char state;
    unsigned char nr_deps;
    unsigned char nr_parents;
};

struct init_op_dep {
    struct init_op *op;
    bool required;
};

#define __INIT_OP_DEPS(fn)  fn ## _init_op_deps
#define INIT_OP_DEPS(fn)    __INIT_OP_DEPS(fn)

#define __INIT_OP(fn)       fn ## _init_op
#define INIT_OP(fn)         __INIT_OP(fn)

#endif /* _KERN_INIT_I_H */
