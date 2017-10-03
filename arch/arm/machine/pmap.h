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

#ifndef _ARM_PMAP_H
#define _ARM_PMAP_H

#include <kern/macros.h>

#define PMAP_START_ADDRESS              DECL_CONST(0, UL)
#define PMAP_END_ADDRESS                DECL_CONST(0xc0000000, UL)

#define PMAP_START_KERNEL_ADDRESS       PMAP_END_ADDRESS
#define PMAP_END_KERNEL_ADDRESS         DECL_CONST(0xfffff000, UL)

#define PMAP_START_DIRECTMAP_ADDRESS    PMAP_END_ADDRESS
#define PMAP_END_DIRECTMAP_ADDRESS      DECL_CONST(0xf8000000, UL)

#define PMAP_START_KMEM_ADDRESS         PMAP_END_DIRECTMAP_ADDRESS
#define PMAP_END_KMEM_ADDRESS           PMAP_END_KERNEL_ADDRESS

#ifndef __ASSEMBLER__

#include <stddef.h>
#include <stdint.h>

#include <kern/cpumap.h>
#include <machine/types.h>

/*
 * Mapping creation flags.
 */
#define PMAP_PEF_GLOBAL 0x1 /* Create a mapping on all processors */

struct pmap;

static inline struct pmap *
pmap_get_kernel_pmap(void)
{
    return NULL;
}

int pmap_kextract(uintptr_t va, phys_addr_t *pap);

int pmap_create(struct pmap **pmapp);

int pmap_enter(struct pmap *pmap, uintptr_t va, phys_addr_t pa,
               int prot, int flags);

int pmap_remove(struct pmap *pmap, uintptr_t va,
                const struct cpumap *cpumap);

int pmap_update(struct pmap *pmap);

void pmap_load(struct pmap *pmap);

/*
 * This init operation provides :
 *  - kernel pmap operations
 */
INIT_OP_DECLARE(pmap_bootstrap);

/*
 * This init operation provides :
 *  - user pmap creation
 *  - module fully initialized
 */
INIT_OP_DECLARE(pmap_setup);

#endif /* __ASSEMBLER__ */

#endif /* _ARM_PMAP_H */
