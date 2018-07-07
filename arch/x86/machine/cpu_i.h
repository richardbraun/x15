/*
 * Copyright (c) 2018 Richard Braun.
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

#ifndef X86_CPU_I_H
#define X86_CPU_I_H

/*
 * EFLAGS register flags.
 */
#define CPU_EFL_ONE 0x00000002  /* Reserved, must be set */
#define CPU_EFL_IF  0x00000200

/*
 * GDT segment selectors.
 *
 * Keep in mind that, on amd64, the size of a GDT entry referred to
 * by a selector depends on the descriptor type.
 */
#define CPU_GDT_SEL_NULL        0
#define CPU_GDT_SEL_CODE        8
#define CPU_GDT_SEL_DATA        16
#define CPU_GDT_SEL_TSS         24

#ifdef __LP64__
#define CPU_GDT_SIZE            40
#else /* __LP64__ */
#define CPU_GDT_SEL_DF_TSS      32
#define CPU_GDT_SEL_PERCPU      40
#define CPU_GDT_SEL_TLS         48
#define CPU_GDT_SIZE            56
#endif /* __LP64__ */

#ifndef __ASSEMBLER__

#include <stdalign.h>
#include <stdbool.h>
#include <stdint.h>

#include <kern/bitmap.h>

struct cpu_tss {
#ifdef __LP64__
    uint32_t reserved0;
    uint64_t rsp0;
    uint64_t rsp1;
    uint64_t rsp2;
    uint64_t ist[8];
    uint64_t reserved1;
    uint16_t reserved2;
#else /* __LP64__ */
    uint32_t link;
    uint32_t esp0;
    uint32_t ss0;
    uint32_t esp1;
    uint32_t ss1;
    uint32_t esp2;
    uint32_t ss2;
    uint32_t cr3;
    uint32_t eip;
    uint32_t eflags;
    uint32_t eax;
    uint32_t ecx;
    uint32_t edx;
    uint32_t ebx;
    uint32_t esp;
    uint32_t ebp;
    uint32_t esi;
    uint32_t edi;
    uint32_t es;
    uint32_t cs;
    uint32_t ss;
    uint32_t ds;
    uint32_t fs;
    uint32_t gs;
    uint32_t ldt;
    uint16_t trap_bit;
#endif /* __LP64__ */
    uint16_t iobp_base;
} __packed;

/*
 * LDT or TSS system segment descriptor.
 */
struct cpu_sysseg_desc {
    uint32_t word1;
    uint32_t word2;
#ifdef __LP64__
    uint32_t word3;
    uint32_t word4;
#endif /* __LP64__ */
};

struct cpu_gdt {
    alignas(CPU_L1_SIZE) char descs[CPU_GDT_SIZE];
};

#define CPU_VENDOR_ID_SIZE  13
#define CPU_MODEL_NAME_SIZE 49

struct cpu_feature_map {
    BITMAP_DECLARE(flags, CPU_NR_FEATURES);
};

struct cpu {
    unsigned int id;
    unsigned int apic_id;
    char vendor_str[CPU_VENDOR_STR_SIZE];
    char model_name[CPU_MODEL_NAME_SIZE];
    unsigned int cpuid_max_basic;
    unsigned int cpuid_max_extended;
    unsigned int vendor_id;
    unsigned int type;
    unsigned int family;
    unsigned int model;
    unsigned int stepping;
    unsigned int clflush_size;
    unsigned int initial_apic_id;
    struct cpu_feature_map feature_map;
    unsigned short phys_addr_width;
    unsigned short virt_addr_width;

    struct cpu_gdt gdt;

    /*
     * TSS segments, one set per CPU.
     *
     * One TSS at least is required per processor to provide the following :
     *  - stacks for double fault handlers, implemented with task switching
     *    on i386, interrupt stack tables on amd64
     *  - stacks for each privilege level
     *  - I/O permission bitmaps
     *
     * See Intel 64 and IA-32 Architecture Software Developer's Manual,
     * Volume 3 System Programming Guide :
     *  - 6.12.2 Interrupt tasks
     *  - 7.3 Task switching
     */
    struct cpu_tss tss;
#ifndef __LP64__
    struct cpu_tss df_tss;
#endif /* __LP64__ */

    unsigned int started;

    alignas(CPU_DATA_ALIGN) char intr_stack[CPU_INTR_STACK_SIZE];
    alignas(CPU_DATA_ALIGN) char df_stack[CPU_INTR_STACK_SIZE];
};

/*
 * This percpu variable contains the address of the percpu area for the local
 * processor. This is normally the same value stored in the percpu module, but
 * it can be directly accessed through a segment register.
 */
extern void *cpu_local_area;

static inline bool
cpu_feature_map_test(const struct cpu_feature_map *map,
                     enum cpu_feature feature)
{
    return bitmap_test(map->flags, feature);
}

/*
 * Return the content of the EFLAGS register.
 *
 * Implies a compiler barrier.
 *
 * TODO Add cpu_flags_t type.
 */
static __always_inline unsigned long
cpu_get_eflags(void)
{
    unsigned long eflags;

    asm volatile("pushf\n"
                 "pop %0\n"
                 : "=r" (eflags)
                 : : "memory");

    return eflags;
}

#endif /* __ASSEMBLER__ */

#endif /* X86_CPU_I_H */
