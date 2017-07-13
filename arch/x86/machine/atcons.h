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
 * AT console driver.
 */

#ifndef _X86_ATCONS_H
#define _X86_ATCONS_H

#include <kern/init.h>

/*
 * Console interrupt handler.
 *
 * This function is called by the AT keyboard interrupt handler
 * to handle machine-independent console management.
 */
void atcons_intr(const char *s);

/*
 * Direction control processing functions.
 */
void atcons_left(void);
void atcons_bottom(void);
void atcons_right(void);
void atcons_up(void);

/*
 * This init operation provides :
 *  - CGA output through the console module
 */
INIT_OP_DECLARE(atcons_bootstrap);

/*
 * This init operation provides :
 *  - AT keyboard input through the console module
 *  - module fully initialized
 */
INIT_OP_DECLARE(atcons_setup);

#endif /* _X86_ATCONS_H */
