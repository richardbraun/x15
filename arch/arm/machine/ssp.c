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
 */

#include <stdint.h>

#include <kern/macros.h>
#include <kern/panic.h>

#ifdef __LP64__
#define SSP_GUARD_WORD 0xdeadd00ddeadd00d
#else
#define SSP_GUARD_WORD 0xdeadd00d
#endif

__used uintptr_t ssp_guard_word = SSP_GUARD_WORD;
__used extern uintptr_t __stack_chk_guard __attribute__((alias("ssp_guard_word")));

void ssp_panic(void);

__used void
ssp_panic(void)
{
    panic("ssp: stack corruption detected");
}

__used void __stack_chk_fail(void) __attribute__((alias("ssp_panic")));
