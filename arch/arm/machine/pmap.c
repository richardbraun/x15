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

#include <kern/error.h>
#include <machine/pmap.h>
#include <machine/types.h>

static int __init
pmap_bootstrap(void)
{
    return 0;
}

INIT_OP_DEFINE(pmap_bootstrap);

int
pmap_kextract(uintptr_t va, phys_addr_t *pap)
{
    (void)va;
    (void)pap;
}

int
pmap_create(struct pmap **pmapp)
{
    (void)pmapp;
    return ERROR_AGAIN;
}

int
pmap_enter(struct pmap *pmap, uintptr_t va, phys_addr_t pa,
           int prot, int flags)
{
    (void)pmap;
    (void)va;
    (void)pa;
    (void)prot;
    (void)flags;
    return ERROR_AGAIN;
}

int
pmap_remove(struct pmap *pmap, uintptr_t va, const struct cpumap *cpumap)
{
    (void)pmap;
    (void)va;
    (void)cpumap;
    return ERROR_AGAIN;
}

int
pmap_update(struct pmap *pmap)
{
    (void)pmap;
    return ERROR_AGAIN;
}

void
pmap_load(struct pmap *pmap)
{
    (void)pmap;
}

static int __init
pmap_setup(void)
{
    return 0;
}

INIT_OP_DEFINE(pmap_setup);
