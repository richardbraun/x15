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

/*
 * Early initialization of the atcons module.
 */
void atcons_bootstrap(void);

/*
 * Initialize the atcons module.
 *
 * This function enables keyboard interrupt handling.
 */
void atcons_setup(void);

/*
 * Console interrupt handler.
 *
 * This function is called by the AT keyboard interrupt handler
 * to handle machine-independent console management.
 */
void atcons_intr(char c);

#endif /* _X86_ATCONS_H */
