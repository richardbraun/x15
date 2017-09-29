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

#include <kern/init.h>

void __init
boot_log_info(void)
{
}

/*
 * Init operation aliases.
 */

static int __init
boot_bootstrap_console(void)
{
    return 0;
}

INIT_OP_DEFINE(boot_bootstrap_console);

static int __init
boot_setup_console(void)
{
    return 0;
}

INIT_OP_DEFINE(boot_setup_console);

static int __init
boot_setup_intr(void)
{
    return 0;
}

INIT_OP_DEFINE(boot_load_vm_page_zones);

static int __init
boot_setup_intr(void)
{
    return 0;
}

INIT_OP_DEFINE(boot_setup_intr);

static int __init
boot_setup_shutdown(void)
{
    return 0;
}

INIT_OP_DEFINE(boot_setup_shutdown);
