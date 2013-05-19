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
 *
 *
 * Processors represented as bit maps.
 *
 * This module acts as a convenient frontend for the bitmap and kmem modules.
 * Since the size of a CPU map varies with the maximum number of processors
 * that can be managed by the system, maps must not be allocated from the
 * stack.
 */

#ifndef _KERN_CPUMAP_H
#define _KERN_CPUMAP_H

#include <kern/bitmap.h>

struct cpumap {
    BITMAP_DECLARE(cpus, MAX_CPUS);
};

static inline void
cpumap_zero(struct cpumap *cpumap)
{
    bitmap_zero(cpumap->cpus, MAX_CPUS);
}

static inline void
cpumap_fill(struct cpumap *cpumap)
{
    bitmap_fill(cpumap->cpus, MAX_CPUS);
}

static inline void
cpumap_copy(struct cpumap *dest, const struct cpumap *src)
{
    bitmap_copy(dest->cpus, src->cpus, MAX_CPUS);
}

static inline void
cpumap_set(struct cpumap *cpumap, int index)
{
    bitmap_set(cpumap->cpus, index);
}

static inline void
cpumap_set_atomic(struct cpumap *cpumap, int index)
{
    bitmap_set_atomic(cpumap->cpus, index);
}

static inline void
cpumap_clear(struct cpumap *cpumap, int index)
{
    bitmap_clear(cpumap->cpus, index);
}

static inline void
cpumap_clear_atomic(struct cpumap *cpumap, int index)
{
    bitmap_clear_atomic(cpumap->cpus, index);
}

static inline int
cpumap_test(const struct cpumap *cpumap, int index)
{
    return bitmap_test(cpumap->cpus, index);
}

static inline int
cpumap_find_next(const struct cpumap *cpumap, int index)
{
    return bitmap_find_next(cpumap->cpus, MAX_CPUS, index);
}

static inline int
cpumap_find_first(const struct cpumap *cpumap)
{
    return bitmap_find_first(cpumap->cpus, MAX_CPUS);
}

static inline int
cpumap_find_next_zero(const struct cpumap *cpumap, int index)
{
    return bitmap_find_next_zero(cpumap->cpus, MAX_CPUS, index);
}

static inline int
cpumap_find_first_zero(const struct cpumap *cpumap)
{
    return bitmap_find_first_zero(cpumap->cpus, MAX_CPUS);
}

#define cpumap_for_each(cpumap, index) \
    bitmap_for_each((cpumap)->cpus, MAX_CPUS, index)

#define cpumap_for_each_zero(cpumap, index) \
    bitmap_for_each_zero((cpumap)->cpus, MAX_CPUS, index)

/*
 * Initialize the cpumap module.
 */
void cpumap_setup(void);

/*
 * Allocate a CPU map.
 *
 * The new map is uninitialized.
 */
int cpumap_create(struct cpumap **cpumapp);

/*
 * Release a CPU map.
 */
void cpumap_destroy(struct cpumap *cpumap);

/*
 * Check the validity of a CPU map.
 *
 * If the map doesn't identify at least one managed processor, return
 * ERROR_INVAL.
 */
int cpumap_check(const struct cpumap *cpumap);

#endif /* _KERN_CPUMAP_H */
