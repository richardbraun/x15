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
 * Stack tracing.
 */

#ifndef _X86_STRACE_H
#define _X86_STRACE_H

#include <kern/macros.h>
#include <machine/multiboot.h>

/*
 * Display a call trace.
 *
 * Attempt to resolve the given instruction pointer, then walk the calling
 * chain from the given frame pointer.
 */
void strace_show(unsigned long ip, unsigned long bp);

/*
 * Display the current call trace.
 */
static __always_inline void
strace_dump(void)
{
    unsigned long ip;

    asm volatile("1: mov $1b, %0" : "=r" (ip));
    strace_show(ip, (unsigned long)__builtin_frame_address(0));
}

/*
 * Setup the stack tracing module.
 *
 * If available, the symbol table is extracted from the boot data.
 */
void strace_setup(const struct multiboot_raw_info *mbi);

#endif /* _X86_STRACE_H */
