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
 * Stack tracing.
 */

#ifndef _ARM_STRACE_H
#define _ARM_STRACE_H

static inline void
strace_dump(void)
{
}

/*
 * This init operation provides :
 *  - module fully initialized
 */
INIT_OP_DECLARE(strace_setup);

#endif /* _ARM_STRACE_H */