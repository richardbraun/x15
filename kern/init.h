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

#ifndef _KERN_INIT_H
#define _KERN_INIT_H

#include <lib/macros.h>

/*
 * These sections should contain code and data which can be discarded once
 * kernel initialization is done.
 */
#define __init __section(".init")
#define __initrodata __section(".initrodata")
#define __initdata __section(".initdata")

#endif /* _KERN_INIT_H */
