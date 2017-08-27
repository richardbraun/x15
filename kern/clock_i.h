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

#ifndef _KERN_CLOCK_I_H
#define _KERN_CLOCK_I_H

#include <stdint.h>

#include <machine/cpu.h>

union clock_global_time {
    alignas(CPU_L1_SIZE) uint64_t ticks;

#ifndef ATOMIC_HAVE_64B_OPS
    struct {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        uint32_t high1;
        uint32_t low;
#else /* __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__ */
        uint32_t low;
        uint32_t high1;
#endif /* __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__ */
        uint32_t high2;
    };
#endif /* ATOMIC_HAVE_64B_OPS */
};

#endif /* _KERN_CLOCK_I_H */
