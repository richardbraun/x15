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
 * Kernel command line argument parsing.
 *
 * Arguments are separated by spaces (there is no escape character).
 * They can be of the form "name" when used as boolean values (present
 * or not), or "name=value".
 */

#ifndef _KERN_ARG_H
#define _KERN_ARG_H

#include <stdbool.h>

#include <kern/init.h>

#define ARG_CMDLINE_MAX_SIZE 256

/*
 * Set the command line string.
 *
 * This function must be called before calling the kernel main entry point.
 */
void arg_set_cmdline(const char *cmdline);

/*
 * Log command line information.
 */
void arg_log_info(void);

/*
 * Return true if an argument with the given name is present in the
 * command line.
 */
bool arg_present(const char *name);

/*
 * Return the value of the argument with the given name in the command
 * line.
 *
 * If the argument form is "name", the empty string is returned. If the
 * argument isn't present, NULL is returned.
 */
const char * arg_value(const char *name);

/*
 * This init operation provides :
 *  - command line arguments can be retrieved
 */
INIT_OP_DECLARE(arg_setup);

#endif /* _KERN_ARG_H */
