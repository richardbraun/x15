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

#include <stdio.h>

#include <kern/init.h>
#include <kern/plist.h>
#include <kern/shell.h>
#include <kern/shutdown.h>
#include <machine/boot.h>
#include <machine/cpu.h>

static struct plist shutdown_ops_list;

#ifdef X15_ENABLE_SHELL

static void
shutdown_shell_halt(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    shutdown_halt();
}

static void
shutdown_shell_reboot(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    shutdown_reboot();
}

static struct shell_cmd shutdown_shell_cmds[] = {
    SHELL_CMD_INITIALIZER("shutdown_halt", shutdown_shell_halt,
        "shutdown_halt",
        "halt the system"),
    SHELL_CMD_INITIALIZER("shutdown_reboot", shutdown_shell_reboot,
        "shutdown_reboot",
        "reboot the system"),
};

static int __init
shutdown_setup_shell(void)
{
    SHELL_REGISTER_CMDS(shutdown_shell_cmds);
    return 0;
}

INIT_OP_DEFINE(shutdown_setup_shell,
               INIT_OP_DEP(shell_setup, true),
               INIT_OP_DEP(shutdown_setup, true));

#endif /* X15_ENABLE_SHELL */

static int __init
shutdown_bootstrap(void)
{
    plist_init(&shutdown_ops_list);
    return 0;
}

INIT_OP_DEFINE(shutdown_bootstrap);

static int __init
shutdown_setup(void)
{
    return 0;
}

INIT_OP_DEFINE(shutdown_setup,
               INIT_OP_DEP(boot_setup_shutdown, true),
               INIT_OP_DEP(cpu_setup, true),
               INIT_OP_DEP(printf_setup, true),
               INIT_OP_DEP(shutdown_bootstrap, true));

void __init
shutdown_register(struct shutdown_ops *ops, unsigned int priority)
{
    plist_node_init(&ops->node, priority);
    plist_add(&shutdown_ops_list, &ops->node);
}

static void
shutdown_halt_other_cpus(void)
{
    cpu_intr_disable();
    cpu_halt_broadcast();
}

void
shutdown_halt(void)
{
    shutdown_halt_other_cpus();
    printf("shutdown: system halted\n");
    cpu_halt();
}

void
shutdown_reboot(void)
{
    struct shutdown_ops *ops;

    if (plist_empty(&shutdown_ops_list)) {
        printf("shutdown: no reset operation available, halting\n");
        shutdown_halt();
    }

    shutdown_halt_other_cpus();
    printf("shutdown: rebooting...\n");

    plist_for_each_entry_reverse(&shutdown_ops_list, ops, node) {
        ops->reset();
    }

    cpu_halt();
}
