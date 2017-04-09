/*
 * Copyright (c) 2010, 2012 Richard Braun.
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

/*
 * These sections should contain code and data which can be discarded once
 * kernel initialization is done.
 */
#define INIT_SECTION        .init.text
#define INIT_DATA_SECTION   .init.data

#ifndef __ASSEMBLER__

#include <kern/macros.h>

#define __init __section(QUOTE(INIT_SECTION))
#define __initdata __section(QUOTE(INIT_DATA_SECTION))

/*
 * Boundaries of the .init section.
 */
extern char _init;
extern char _init_end;

#endif /* __ASSEMBLER__ */

#endif /* _KERN_INIT_H */
