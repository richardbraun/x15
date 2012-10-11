/*
 * Copyright (c) 2010, 2012 Richard Braun.
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
 * Early initialization procedure for x86.
 *
 * This module is separated in assembly and C code. The former is where
 * the first instructions are run, and where actions that aren't possible,
 * easy or clean in C are performed.
 *
 * When the boot loader passes control to the kernel, the main processor is
 * in protected mode, paging is disabled, and some boot data are availabe
 * outside the kernel. This module first sets up a basic physical memory
 * allocator so that it can allocate page tables without corrupting the
 * boot data. The .init section is linked at physical addresses, so that
 * it can run with and without paging enabled. The page tables must properly
 * configure an identity mapping so that this remains true as long as
 * initialization code and data are used. Once the VM system is available,
 * boot data are copied in kernel allocated buffers and their original pages
 * are freed.
 *
 * On amd64, 64-bit code cannot run in legacy or compatibility mode. In order
 * to walk the boot data structures, the kernel must either run 32-bit code
 * (e.g. converting ELF32 to ELF64 objects before linking them) or establish
 * a temporary identity mapping for the first 4 GiB of physical memory. As a
 * way to simplify development, and make it possible to use 64-bit code
 * almost everywhere, the latter solution is implemented (a small part of
 * 32-bit code is required until the identity mapping is in place).
 */

#include <kern/init.h>
#include <kern/kmem.h>
#include <kern/kernel.h>
#include <kern/panic.h>
#include <kern/param.h>
#include <lib/stddef.h>
#include <lib/stdint.h>
#include <lib/string.h>
#include <machine/biosmem.h>
#include <machine/boot.h>
#include <machine/cpu.h>
#include <machine/multiboot.h>
#include <machine/pit.h>
#include <machine/pmap.h>
#include <machine/vga.h>
#include <vm/vm_kmem.h>
#include <vm/vm_page.h>
#include <vm/vm_phys.h>
#include <vm/vm_setup.h>

/*
 * Macros used by the very early panic function.
 */
#define INIT_VGAMEM     ((uint16_t *)0xb8000)
#define INIT_VGACHARS   (80 * 25)
#define INIT_VGACOLOR   0x7

char boot_stack[BOOT_STACK_SIZE] __aligned(DATA_ALIGN) __initdata;
char boot_ap_stack[BOOT_STACK_SIZE] __aligned(DATA_ALIGN) __initdata;
unsigned long boot_ap_id __initdata;
unsigned long boot_ap_stack_addr __initdata;

#ifdef __LP64__
pmap_pte_t boot_pml4[PMAP_PTE_PER_PT] __aligned(PAGE_SIZE) __initdata;
pmap_pte_t boot_pdpt[PMAP_PTE_PER_PT] __aligned(PAGE_SIZE) __initdata;
pmap_pte_t boot_pdir[4 * PMAP_PTE_PER_PT] __aligned(PAGE_SIZE) __initdata;
#endif /* __LP64__ */

/*
 * Copy of the multiboot data passed by the boot loader.
 */
static struct multiboot_info boot_mbi __initdata;

void __init
boot_panic(const char *msg)
{
    uint16_t *ptr, *end;
    const char *s;

    ptr = INIT_VGAMEM;
    end = ptr + INIT_VGACHARS;

    s = (const char *)BOOT_VTOP("panic: ");

    while ((ptr < end) && (*s != '\0'))
        *ptr++ = (INIT_VGACOLOR << 8) | *s++;

    s = (const char *)BOOT_VTOP(msg);

    while ((ptr < end) && (*s != '\0'))
        *ptr++ = (INIT_VGACOLOR << 8) | *s++;

    while (ptr < end)
        *ptr++ = (INIT_VGACOLOR << 8) | ' ';

    cpu_halt();

    /* Never reached */
}

pmap_pte_t * __init
boot_setup_paging(uint32_t eax, const struct multiboot_info *mbi)
{
    if (eax != MULTIBOOT_LOADER_MAGIC)
        boot_panic("not started by a multiboot compliant boot loader");

    if (!(mbi->flags & MULTIBOOT_LOADER_MEMORY))
        boot_panic("missing basic memory information");

#ifdef __LP64__
    boot_panic("64-bit long mode successfully enabled");
#endif

    /*
     * Save the multiboot data passed by the boot loader, initialize the
     * bootstrap allocator and set up paging.
     */
    boot_mbi = *mbi;
    biosmem_bootstrap(&boot_mbi);
    return pmap_setup_paging();
}

/*
 * Copy physical memory into a kernel allocated buffer.
 */
static void * __init
boot_save_boot_data_copy(const void *ptr, size_t size)
{
    unsigned long map_addr;
    size_t map_size;
    const void *src;
    void *copy;

    src = vm_kmem_map_pa((unsigned long)ptr, size, &map_addr, &map_size);

    if (src == NULL)
        panic("unable to map boot data in kernel map");

    copy = kmem_alloc(size);

    if (copy == NULL)
        panic("unable to allocate memory for boot data copy");

    memcpy(copy, src, size);
    vm_kmem_unmap_pa(map_addr, map_size);
    return copy;
}

/*
 * Copy boot data in kernel allocated memory.
 *
 * At this point, the only required boot data are the modules and the command
 * line strings. Once the boot data are managed as kernel buffers, their
 * backing pages can be freed.
 *
 * TODO Handle more boot data such as debugging symbols.
 */
static void __init
boot_save_boot_data(void)
{
    uint32_t i;

    if (boot_mbi.flags & MULTIBOOT_LOADER_CMDLINE)
        boot_mbi.cmdline = boot_save_boot_data_copy(boot_mbi.cmdline,
                                                    boot_mbi.unused0);
    else
        boot_mbi.cmdline = NULL;

    if (boot_mbi.flags & MULTIBOOT_LOADER_MODULES) {
        struct multiboot_module *mod;
        size_t size;

        size = boot_mbi.mods_count * sizeof(struct multiboot_module);
        boot_mbi.mods_addr = boot_save_boot_data_copy(boot_mbi.mods_addr, size);

        for (i = 0; i < boot_mbi.mods_count; i++) {
            mod = &boot_mbi.mods_addr[i];
            size = mod->mod_end - mod->mod_start;
            mod->mod_start = boot_save_boot_data_copy(mod->mod_start, size);
            mod->mod_end = mod->mod_start + size;

            if (mod->string != NULL)
                mod->string = boot_save_boot_data_copy(mod->string,
                                                       mod->reserved);
        }
    } else {
        boot_mbi.mods_count = 0;
        boot_mbi.mods_addr = NULL;
    }
}

void __init
boot_main(void)
{
    cpu_setup();
    pmap_bootstrap();
    vga_setup();
    kernel_show_banner();
    cpu_check(cpu_current());
    cpu_info(cpu_current());
    biosmem_setup();
    vm_setup();
    boot_save_boot_data();
    biosmem_free_usable();
    vm_phys_info();
    pit_setup();
    cpu_mp_setup();
    kernel_main();

    /* Never reached */
}

void __init
boot_ap(void)
{
    cpu_ap_setup();
    cpu_info(cpu_current());

    cpu_intr_enable();

    for (;;)
        cpu_idle();

    /* Never reached */
}
