/*
 * Copyright (c) 2015 Richard Braun.
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
 * Minimalist shell for embedded systems.
 */

#ifndef _KERN_SHELL_H
#define _KERN_SHELL_H

#include <kern/init.h>
#include <kern/error.h>
#include <kern/macros.h>

#ifdef X15_ENABLE_SHELL

#define SHELL_REGISTER_CMDS(cmds)                           \
MACRO_BEGIN                                                 \
    size_t ___i;                                            \
    int ___error;                                           \
                                                            \
    for (___i = 0; ___i < ARRAY_SIZE(cmds); ___i++) {       \
        ___error = shell_cmd_register(&(cmds)[___i]);       \
        error_check(___error, __func__);                    \
    }                                                       \
MACRO_END

typedef void (*shell_fn_t)(int argc, char *argv[]);

struct shell_cmd {
    struct shell_cmd *ht_next;
    struct shell_cmd *ls_next;
    const char *name;
    shell_fn_t fn;
    const char *usage;
    const char *short_desc;
    const char *long_desc;
};

/*
 * Static shell command initializers.
 */
#define SHELL_CMD_INITIALIZER(name, fn, usage, short_desc) \
    { NULL, NULL, name, fn, usage, short_desc, NULL }
#define SHELL_CMD_INITIALIZER2(name, fn, usage, short_desc, long_desc) \
    { NULL, NULL, name, fn, usage, short_desc, long_desc }

/*
 * Initialize a shell command structure.
 */
void shell_cmd_init(struct shell_cmd *cmd, const char *name,
                    shell_fn_t fn, const char *usage,
                    const char *short_desc, const char *long_desc);

/*
 * Start the shell thread.
 */
void shell_start(void);

/*
 * Register a shell command.
 *
 * The command name must be unique. It must not include characters outside
 * the [a-zA-Z0-9-_] class.
 *
 * The structure passed when calling this function is directly reused by
 * the shell module and must persist in memory.
 */
int shell_cmd_register(struct shell_cmd *cmd);

#else /* X15_ENABLE_SHELL */
#define SHELL_REGISTER_CMDS(cmds)
#define shell_setup()
#define shell_start()
#endif /* X15_ENABLE_SHELL */

/*
 * This init operation provides :
 *  - commands can be registered
 *  - module fully initialized
 */
INIT_OP_DECLARE(shell_setup);

#endif /* _KERN_SHELL_H */
