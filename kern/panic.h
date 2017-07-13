/*
 * Copyright (c) 2010 Richard Braun.
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

#ifndef _KERN_PANIC_H
#define _KERN_PANIC_H

#include <stdnoreturn.h>

#include <kern/init.h>

/*
 * Print the given message and halt the system immediately.
 */
noreturn void panic(const char *format, ...)
    __attribute__((format(printf, 1, 2)));

/*
 * This init operation provides :
 *  - module fully initialized
 */
INIT_OP_DECLARE(panic_setup);

#endif /* _KERN_PANIC_H */
