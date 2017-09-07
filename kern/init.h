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
 * Init sections and operations.
 */

#ifndef _KERN_INIT_H
#define _KERN_INIT_H

/*
 * These sections should contain code and data which can be discarded once
 * kernel initialization is done.
 */
#define INIT_SECTION        .init.text
#define INIT_DATA_SECTION   .init.data

/*
 * This section must only contain init operation structures, and must be
 * located inside the .init section.
 */
#define INIT_OPS_SECTION    .init.ops

/*
 * Alignment is important to make sure initialization operations are
 * stored as a C array in the reserved init op section.
 */
#define INIT_OP_ALIGN 64

#ifndef __ASSEMBLER__

#include <kern/error.h>
#include <kern/macros.h>

#define __init __section(QUOTE(INIT_SECTION))
#define __initdata __section(QUOTE(INIT_DATA_SECTION))

/*
 * Boundaries of the .init section.
 */
extern char _init;
extern char _init_end;

/*
 * Type for initialization operation functions.
 */
typedef int (*init_op_fn_t)(void);

#include <kern/init_i.h>

/*
 * Forge an init operation declaration.
 */
#define INIT_OP_DECLARE(fn) extern struct init_op INIT_OP(fn)

/*
 * Foge an entry suitable as an init operation dependency.
 *
 * If a dependency isn't required, it's still used to determine run
 * order, but its result is ignored, and the operation depending on it
 * behaves as if that dependency succeeded.
 */
#define INIT_OP_DEP(fn, required) { &INIT_OP(fn), required }

/*
 * Init operation definition macro.
 *
 * This macro is used to define a structure named after the given function.
 * Init operations are placed in a specific section which doesn't contain
 * any other object type, making it a system-wide array of init operations.
 * There is no need to actively register init operations; this module finds
 * them all from their section. Dependencies are given as a variable-length
 * argument list of entries built with the INIT_OP_DEP() macro.
 */
#define INIT_OP_DEFINE(_fn, ...)                                    \
    static struct init_op_dep INIT_OP_DEPS(_fn)[] __initdata = {    \
        __VA_ARGS__                                                 \
    };                                                              \
                                                                    \
    struct init_op INIT_OP(_fn) __initop __used = {                 \
        .name = QUOTE(_fn),                                         \
        .fn = _fn,                                                  \
        .deps = INIT_OP_DEPS(_fn),                                  \
        .error = ERROR_AGAIN,                                       \
        .state = INIT_OP_STATE_UNLINKED,                            \
        .nr_deps = ARRAY_SIZE(INIT_OP_DEPS(_fn)),                   \
        .nr_parents = 0,                                            \
    }

/*
 * Initialize the init module.
 *
 * Scan the section containing init operations, resolve all dependencies,
 * and run operations in an appropriate order.
 */
void init_setup(void);

#endif /* __ASSEMBLER__ */

#endif /* _KERN_INIT_H */
