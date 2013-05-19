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

#include <kern/bitmap.h>
#include <kern/cpumap.h>
#include <kern/error.h>
#include <kern/kmem.h>
#include <kern/stddef.h>

static struct kmem_cache cpumap_cache;

void
cpumap_setup(void)
{
    kmem_cache_init(&cpumap_cache, "cpumap", sizeof(struct cpumap),
                    0, NULL, NULL, NULL, 0);
}

int
cpumap_create(struct cpumap **cpumapp)
{
    struct cpumap *cpumap;

    cpumap = kmem_cache_alloc(&cpumap_cache);

    if (cpumap == NULL)
        return ERROR_NOMEM;

    *cpumapp = cpumap;
    return 0;
}

void
cpumap_destroy(struct cpumap *cpumap)
{
    kmem_cache_free(&cpumap_cache, cpumap);
}

int
cpumap_check(const struct cpumap *cpumap)
{
    int index;

    index = bitmap_find_first(cpumap->cpus, cpu_count());

    if (index == -1)
        return ERROR_INVAL;

    return 0;
}
