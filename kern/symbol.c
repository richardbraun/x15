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

#include <stddef.h>
#include <stdint.h>

#include <kern/macros.h>
#include <kern/symbol.h>

/*
 * XXX Clang doesn't consider that weak symbols may change at link time
 * by default, which turns the lookup into a no-op when optimizations
 * are enabled. Make these variables volatile to work around this issue.
 */
const volatile size_t symbol_table_size __weak;
const struct symbol * volatile symbol_table_ptr __weak;

const struct symbol *
symbol_lookup(uintptr_t addr)
{
    const struct symbol *table, *symbol;
    uintptr_t start, end;
    size_t size;

    table = symbol_table_ptr;
    size = symbol_table_size;

    for (size_t i = 0; i < size; i++) {
        symbol = &table[i];

        if (!symbol->name || (symbol->size == 0)) {
            continue;
        }

        start = symbol->addr;
        end = symbol->addr + symbol->size;

        if ((addr >= start) && (addr < end)) {
            return symbol;
        }
    }

    return NULL;
}
