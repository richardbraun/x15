/*
 * Copyright (c) 2012 Richard Braun.
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
 * Information gathering module, supporting the Intel MultiProcessor
 * Specification v1.4.
 */

#ifndef _I386_MPS_H
#define _I386_MPS_H

/*
 * Load multiprocessor information.
 *
 * Return 0 if successful (an error usually means hardware doesn't support
 * the MPS).
 */
int mps_setup(void);

#endif /* _I386_MPS_H */
