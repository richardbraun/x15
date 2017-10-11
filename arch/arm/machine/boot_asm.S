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

#include <machine/asm.h>
#include <machine/boot.h>
#include <machine/pmap.h>
#include <machine/pmem.h>

.section BOOT_LOAD_SECTION, "awx"

ASM_DATA(boot_exception_table):
 .long _start   /* Reset */
 .long 0        /* Undefined instruction */
 .long 0        /* Software interrupt */
 .long 0        /* Prefetch abort */
 .long 0        /* Data abort */
 .long 0        /* IRQ */
 .long 0        /* FIQ */
ASM_END(boot_exception_table)

ASM_FUNC(_start):
 /*
  * Assume the code runs from flash. For the sake of simplicity, make
  * the kernel run from RAM. This requires relocating it, and since the
  * RAM size isn't known, we can't use it for a stack. As a result,
  * perform the relocation in assembly without using a stack.
  */
 ldr %r5, =(PMEM_RAM_START)             /* Load RAM address in %r5 */
 mov %r6, #0                            /* Load kernel address in %r6 */
 ldr %r0, boot_kernel_end               /* Load kernel end virtual address
                                           in %r0 */
 ldr %r1, =(PMAP_START_KERNEL_ADDRESS)  /* Load kernel virtual address in %r1 */
 sub %r7, %r0, %r1                      /* Compute kernel size in bytes */
 lsr %r7, %r7, #2                       /* Compute kernel size in words */

 sub %r5, %r5, #4                       /* Prepare for auto-increment */
 sub %r6, %r6, #4

1:
 ldr %r0, [%r6, #4]!                    /* Load word with auto-increment */
 str %r0, [%r5, #4]!                    /* Store word with auto-increment */
 sub %r7, %r7, #1                       /* Account for the written word */
 cmp %r7, #0                            /* Check the number of words left */
 beq 1f                                 /* Break if copy complete */
 b 1b                                   /* Continue otherwise */

1:
 /*
  * Relocation is done. Make sure that the processor actually runs kernel
  * code by flushing all the relevant caches.
  *
  * Also, in preparation for paging, disable all caches.
  *
  * The reference manual only suggests disabling the instruction cache
  * (B4.2.3 Enabling and disabling the MMU) but the instruction cache may
  * be unified.
  */
 mrc p15, 0, %r0, c1, c0, 0             /* Read CP15 control register */
 bic %r0, %r0, #0x2                     /* Clear the C bit */
 bic %r0, %r0, #0x1000                  /* Clear the I bit */
 mcr p15, 0, %r0, c1, c0, 0             /* Write CP15 control register */
 mov %r0, #0
 mcr p15, 0, %r0, c7, c7, 0             /* Clean all caches */
 mcr p15, 0, %r0, c7, c10, 5            /* Data synchronization barrier */
 mcr p15, 0, %r0, c7, c5, 4             /* Flush prefetch buffer */

 b boot_start_ram                       /* Branch to kernel code in RAM */
ASM_END(_start)

boot_kernel_end:
 .long _end

.section BOOT_TEXT_SECTION, "awx"

ASM_FUNC(boot_start_ram):
 ldr %r13, boot_stack_addr              /* Set up the boot stack */
 add %r13, %r13, #BOOT_STACK_SIZE

 bl boot_setup_paging

 mcr p15, 0, %r0, c2, c0, 0             /* Load the root page table address */
 mov %r0, #1
 mcr p15, 0, %r0, c3, c0, 0             /* Set domain 0 access to client */
 mrc p15, 0, %r0, c1, c0, 0             /* Read CP15 control register */
 orr %r0, %r0, #1                       /* Set the M bit */
 mcr p15, 0, %r0, c1, c0, 0             /* Write CP15 control register */

 /* Never reached */
 b .
ASM_END(boot_start_ram)

boot_stack_addr:
 .long boot_stack
