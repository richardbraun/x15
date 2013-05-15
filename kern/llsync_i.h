/*
 * Copyright (c) 2013 Richard Braun.
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

#ifndef _KERN_LLSYNC_I_H
#define _KERN_LLSYNC_I_H

#include <kern/param.h>

/*
 * Per-processor flag indicating if a processor checked in.
 */
struct llsync_cpu_checkpoint {
    int checked;
} __aligned(CPU_L1_SIZE);

extern struct llsync_cpu_checkpoint llsync_cpu_checkpoints[MAX_CPUS];

#endif /* _KERN_LLSYNC_I_H */
