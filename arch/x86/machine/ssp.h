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

#ifndef _X86_SSP_H
#define _X86_SSP_H

#ifdef __LP64__
#define SSP_GUARD_WORD 0xdeadd00ddeadd00d
#else
#define SSP_GUARD_WORD 0xdeadd00d
#endif

/*
 * Offset, in words, of the SSP guard word.
 */
#define SSP_WORD_TLS_OFFSET 5

#endif /* _X86_SSP_H */
