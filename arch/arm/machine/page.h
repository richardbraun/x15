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
 * This file is a top header in the inclusion hierarchy, and shouldn't include
 * other headers that may cause circular dependencies.
 */

#ifndef _ARM_PAGE_H
#define _ARM_PAGE_H

#define PAGE_BITS   12
#define PAGE_SHIFT  PAGE_BITS
#define PAGE_SIZE   (1 << PAGE_BITS)
#define PAGE_MASK   (PAGE_BITS - 1)

#endif /* _ARM_PAGE_H */
