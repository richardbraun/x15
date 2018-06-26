/*
 * Copyright (c) 2018 Agustina Arzille.
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

#ifndef KERN_SYMBOL_H
#define KERN_SYMBOL_H

#include <stdint.h>

#include <kern/macros.h>

#define __symbol_table __section(".symbol")

/*
 * Symbol structure.
 *
 * This structure is public.
 */
struct symbol {
    uintptr_t addr;
    uintptr_t size;
    const char *name;
};

/*
 * Look up a symbol from an address.
 *
 * NULL is returned if no symbol was found for the given address.
 */
const struct symbol * symbol_lookup(uintptr_t addr);

#endif /* KERN_SYMBOL_H */
