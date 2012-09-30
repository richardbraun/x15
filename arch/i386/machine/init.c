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
#include <machine/init.h>
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

char init_stack[BOOT_STACK_SIZE] __initdata;
char init_ap_stack[BOOT_STACK_SIZE] __initdata;
unsigned long init_ap_id __initdata;
unsigned long init_ap_boot_stack __initdata;

/*
 * Copy of the multiboot data passed by the boot loader.
 */
static struct multiboot_info init_mbi __initdata;

void __boot
init_panic(const char *msg)
{
    uint16_t *ptr, *end;
    const char *s;

    ptr = INIT_VGAMEM;
    end = ptr + INIT_VGACHARS;

    s = (const char *)BOOT_ADDR_VTOP("boot panic: ");

    while ((ptr < end) && (*s != '\0'))
        *ptr++ = (INIT_VGACOLOR << 8) | *s++;

    s = (const char *)BOOT_ADDR_VTOP(msg);

    while ((ptr < end) && (*s != '\0'))
        *ptr++ = (INIT_VGACOLOR << 8) | *s++;

    while (ptr < end)
        *ptr++ = (INIT_VGACOLOR << 8) | ' ';

    cpu_halt();

    /* Never reached */
}

pmap_pte_t * __boot
init_paging(uint32_t eax, const struct multiboot_info *mbi)
{
    pmap_pte_t *pdir, *ptps, *pte, *id_pte;
    unsigned long i, nr_pages, nr_ptps, kern_start, kern_end;

    if (eax != MULTIBOOT_LOADER_MAGIC)
        init_panic("not started by a multiboot compliant boot loader");

    if (!(mbi->flags & MULTIBOOT_LOADER_MEMORY))
        init_panic("missing basic memory information");

    /*
     * Save the multiboot data passed by the boot loader and initialize the
     * bootstrap allocator.
     */
    BOOT_VTOP(init_mbi) = *mbi;
    biosmem_bootstrap(&BOOT_VTOP(init_mbi));

    /*
     * Create the kernel virtual mapping. Two mappings are actually established,
     * using the same PTPs: a direct physical mapping, where virtual and
     * physical addresses are identical (the identity mapping), and the true
     * kernel mapping at KERNEL_OFFSET. The identity mapping is required to
     * avoid a fault directly after paging is enabled. In addition, a few pages
     * are reserved immediately after the kernel for the pmap module.
     *
     * While only the kernel is mapped, the PTPs are initialized so that all
     * memory from KERNEL_OFFSET up to the pmap reserved pages can be mapped,
     * which is required by pmap_growkernel().
     */

    /* Allocate the PTPs */
    kern_end = BOOT_ADDR_VTOP(&_end);
    nr_pages = (kern_end / PAGE_SIZE) + PMAP_RESERVED_PAGES;
    nr_ptps = P2ROUND(nr_pages, PMAP_PTE_PER_PT) / PMAP_PTE_PER_PT;
    ptps = biosmem_bootalloc(nr_ptps);

    /* Insert the PTPs in the page directory */
    pdir = (pmap_pte_t *)BOOT_ADDR_VTOP(pmap_kpdir);
    pte = pdir + (KERNEL_OFFSET >> PMAP_PDE_SHIFT);
    id_pte = pdir;

    for (i = 0; i < nr_ptps; i++) {
        *pte = ((unsigned long)ptps + (i * PAGE_SIZE))
               | PMAP_PTE_WRITE | PMAP_PTE_PRESENT;
        *id_pte++ = *pte++;
    }

    /* Map the kernel */
    kern_start = (unsigned long)&_boot;

    for (i = kern_start; i < kern_end; i += PAGE_SIZE)
        ptps[vm_page_atop(i)] = i | PMAP_PTE_WRITE | PMAP_PTE_PRESENT;

#ifdef PAE
    pte = (pmap_pte_t *)BOOT_ADDR_VTOP(pmap_kpdpt);

    for (i = 0; i < PMAP_NR_PDT; i++)
        pte[i] = ((unsigned long)pdir + (i * PAGE_SIZE)) | PMAP_PTE_PRESENT;

    cpu_enable_pae();

    return pte;
#else /* PAE */
    return pdir;
#endif /* PAE */
}

pmap_pte_t * __boot
init_ap_paging(void)
{
#ifdef PAE
    cpu_enable_pae();
    return (pmap_pte_t *)BOOT_ADDR_VTOP(pmap_kpdpt);
#else /* PAE */
    return (pmap_pte_t *)BOOT_ADDR_VTOP(pmap_kpdir);
#endif /* PAE */
}

/*
 * Copy physical memory into a kernel allocated buffer.
 */
static void * __init
init_save_boot_data_copy(const void *ptr, size_t size)
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
init_save_boot_data(void)
{
    uint32_t i;

    if (init_mbi.flags & MULTIBOOT_LOADER_CMDLINE)
        init_mbi.cmdline = init_save_boot_data_copy(init_mbi.cmdline,
                                                    init_mbi.unused0);
    else
        init_mbi.cmdline = NULL;

    if (init_mbi.flags & MULTIBOOT_LOADER_MODULES) {
        struct multiboot_module *mod;
        size_t size;

        size = init_mbi.mods_count * sizeof(struct multiboot_module);
        init_mbi.mods_addr = init_save_boot_data_copy(init_mbi.mods_addr, size);

        for (i = 0; i < init_mbi.mods_count; i++) {
            mod = &init_mbi.mods_addr[i];
            size = mod->mod_end - mod->mod_start;
            mod->mod_start = init_save_boot_data_copy(mod->mod_start, size);
            mod->mod_end = mod->mod_start + size;

            if (mod->string != NULL)
                mod->string = init_save_boot_data_copy(mod->string,
                                                       mod->reserved);
        }
    } else {
        init_mbi.mods_count = 0;
        init_mbi.mods_addr = NULL;
    }
}

void __init
init(void)
{
    cpu_setup();
    pmap_bootstrap();
    vga_setup();
    kernel_show_banner();
    cpu_check(cpu_current());
    cpu_info(cpu_current());
    biosmem_setup();
    vm_setup();
    init_save_boot_data();
    biosmem_free_usable();
    vm_phys_info();
    pit_setup();
    cpu_mp_setup();
    kernel_main();

    /* Never reached */
}

void __init
init_ap(void)
{
    cpu_ap_setup();
    cpu_info(cpu_current());

    cpu_intr_enable();

    for (;;)
        cpu_idle();

    /* Never reached */
}
