/*
 * Copyright (c) 2010-2017 Richard Braun.
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
 * boot data. The .boot section is linked at physical addresses, so that
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
 * 32-bit code is required until the identity mapping is in place). Mentions
 * to "enabling paging" do not refer to this initial identity mapping.
 *
 * TODO EFI support.
 */

#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <kern/arg.h>
#include <kern/init.h>
#include <kern/kmem.h>
#include <kern/kernel.h>
#include <kern/log.h>
#include <kern/macros.h>
#include <kern/panic.h>
#include <kern/thread.h>
#include <machine/acpi.h>
#include <machine/atcons.h>
#include <machine/biosmem.h>
#include <machine/boot.h>
#include <machine/cga.h>
#include <machine/cpu.h>
#include <machine/elf.h>
#include <machine/multiboot.h>
#include <machine/page.h>
#include <machine/pmap.h>
#include <machine/strace.h>
#include <machine/uart.h>
#include <vm/vm_kmem.h>

alignas(CPU_DATA_ALIGN) char boot_stack[BOOT_STACK_SIZE] __bootdata;
alignas(CPU_DATA_ALIGN) char boot_ap_stack[BOOT_STACK_SIZE] __bootdata;
unsigned int boot_ap_id __bootdata;

#ifdef __LP64__
alignas(PAGE_SIZE) pmap_pte_t boot_pml4[PMAP_L3_PTES_PER_PT] __bootdata;
alignas(PAGE_SIZE) pmap_pte_t boot_pdpt[PMAP_L2_PTES_PER_PT] __bootdata;
alignas(PAGE_SIZE) pmap_pte_t boot_pdir[4 * PMAP_L1_PTES_PER_PT] __bootdata;
char boot_panic_long_mode_msg[] __bootdata
    = "boot: processor doesn't support long mode";
#endif /* __LP64__ */

struct cpu_tls_seg boot_tls_seg __bootdata = {
    .ssp_guard_word = SSP_GUARD_WORD,
};

/*
 * This TLS segment descriptor is copied early at boot time into the
 * temporary boot GDT. However, it is incomplete. Assembly code
 * completes it before writing it into the boot GDT before calling
 * any C function, since those may require the TLS segment ready if
 * stack protection is enabled.
 */
struct cpu_seg_desc boot_tls_seg_desc __bootdata = {
    .low = (sizeof(boot_tls_seg) & 0xffff),

    .high = CPU_DESC_DB
            | ((sizeof(boot_tls_seg) >> 16) & 0xf)
            | CPU_DESC_PRESENT
            | CPU_DESC_S
            | CPU_DESC_TYPE_DATA,
};

/*
 * Copies of the multiboot data passed by the boot loader.
 */
static struct multiboot_raw_info boot_raw_mbi __bootdata;
static struct multiboot_info boot_mbi __initdata;

static char boot_tmp_cmdline[ARG_CMDLINE_MAX_SIZE] __bootdata;

static char boot_panic_intro_msg[] __bootdata = "panic: ";
static char boot_panic_loader_msg[] __bootdata
    = "boot: not started by a multiboot compliant boot loader";
static char boot_panic_meminfo_msg[] __bootdata
    = "boot: missing basic memory information";
static char boot_panic_cmdline_msg[] __bootdata
    = "boot: command line too long";

void * __boot
boot_memcpy(void *dest, const void *src, size_t n)
{
    const char *src_ptr;
    char *dest_ptr;
    size_t i;

    dest_ptr = dest;
    src_ptr = src;

    for (i = 0; i < n; i++) {
        *dest_ptr = *src_ptr;
        dest_ptr++;
        src_ptr++;
    }

    return dest;
}

void * __boot
boot_memmove(void *dest, const void *src, size_t n)
{
    const char *src_ptr;
    char *dest_ptr;
    size_t i;

    if (dest <= src) {
        dest_ptr = dest;
        src_ptr = src;

        for (i = 0; i < n; i++) {
            *dest_ptr = *src_ptr;
            dest_ptr++;
            src_ptr++;
        }
    } else {
        dest_ptr = dest + n - 1;
        src_ptr = src + n - 1;

        for (i = 0; i < n; i++) {
            *dest_ptr = *src_ptr;
            dest_ptr--;
            src_ptr--;
        }
    }

    return dest;
}

void * __boot
boot_memset(void *s, int c, size_t n)
{
    char *buffer;
    size_t i;

    buffer = s;

    for (i = 0; i < n; i++) {
        buffer[i] = c;
    }

    return s;
}

size_t __boot
boot_strlen(const char *s)
{
    const char *start;

    start = s;

    while (*s != '\0') {
        s++;
    }

    return (s - start);
}

void __boot
boot_panic(const char *msg)
{
    uint16_t *ptr, *end;
    const char *s;

    ptr = (uint16_t *)BOOT_CGAMEM;
    end = ptr + BOOT_CGACHARS;

    s = boot_panic_intro_msg;

    while ((ptr < end) && (*s != '\0')) {
        *ptr = (BOOT_CGACOLOR << 8) | *s;
        ptr++;
        s++;
    }

    s = msg;

    while ((ptr < end) && (*s != '\0')) {
        *ptr = (BOOT_CGACOLOR << 8) | *s;
        ptr++;
        s++;
    }

    while (ptr < end) {
        *ptr = (BOOT_CGACOLOR << 8) | ' ';
        ptr++;
    }

    cpu_halt();

    /* Never reached */
}

static void __boot
boot_save_mod_cmdline_sizes(struct multiboot_raw_info *mbi)
{
    struct multiboot_raw_module *mod;
    uint32_t i;

    if (mbi->flags & MULTIBOOT_LOADER_MODULES) {
        uintptr_t addr;

        addr = mbi->mods_addr;

        for (i = 0; i < mbi->mods_count; i++) {
            mod = (struct multiboot_raw_module *)addr + i;
            mod->reserved = boot_strlen((char *)(uintptr_t)mod->string) + 1;
        }
    }
}

static void __boot
boot_register_data(const struct multiboot_raw_info *mbi)
{
    struct multiboot_raw_module *mod;
    struct elf_shdr *shdr;
    uintptr_t tmp;
    unsigned int i;

    biosmem_register_boot_data((uintptr_t)&_boot,
                               BOOT_VTOP((uintptr_t)&_end), false);

    if (mbi->flags & MULTIBOOT_LOADER_MODULES) {
        i = mbi->mods_count * sizeof(struct multiboot_raw_module);
        biosmem_register_boot_data(mbi->mods_addr, mbi->mods_addr + i, true);

        tmp = mbi->mods_addr;

        for (i = 0; i < mbi->mods_count; i++) {
            mod = (struct multiboot_raw_module *)tmp + i;
            biosmem_register_boot_data(mod->mod_start, mod->mod_end, true);

            if (mod->string != 0) {
                biosmem_register_boot_data(mod->string,
                                           mod->string + mod->reserved, true);
            }
        }
    }

    if (mbi->flags & MULTIBOOT_LOADER_SHDR) {
        tmp = mbi->shdr_num * mbi->shdr_size;
        biosmem_register_boot_data(mbi->shdr_addr, mbi->shdr_addr + tmp, true);

        tmp = mbi->shdr_addr;

        for (i = 0; i < mbi->shdr_num; i++) {
            shdr = (struct elf_shdr *)(tmp + (i * mbi->shdr_size));

            if ((shdr->type != ELF_SHT_SYMTAB)
                && (shdr->type != ELF_SHT_STRTAB)) {
                continue;
            }

            biosmem_register_boot_data(shdr->addr, shdr->addr + shdr->size, true);
        }
    }
}

pmap_pte_t * __boot
boot_setup_paging(struct multiboot_raw_info *mbi, unsigned long eax)
{
    if (eax != MULTIBOOT_LOADER_MAGIC) {
        boot_panic(boot_panic_loader_msg);
    }

    if (!(mbi->flags & MULTIBOOT_LOADER_MEMORY)) {
        boot_panic(boot_panic_meminfo_msg);
    }

    /*
     * Save the multiboot data passed by the boot loader, initialize the
     * bootstrap allocator and set up paging.
     */
    boot_memmove(&boot_raw_mbi, mbi, sizeof(boot_raw_mbi));

    /*
     * The kernel command line must be passed as early as possible to the
     * arg module so that other modules can look up options. Instead of
     * mapping it later, make a temporary copy.
     */
    if (!(mbi->flags & MULTIBOOT_LOADER_CMDLINE)) {
        boot_tmp_cmdline[0] = '\0';
    } else {
        uintptr_t addr;
        size_t length;

        addr = mbi->cmdline;
        length = boot_strlen((const char *)addr) + 1;

        if (length > ARRAY_SIZE(boot_tmp_cmdline)) {
            boot_panic(boot_panic_cmdline_msg);
        }

        boot_memcpy(boot_tmp_cmdline, (const char *)addr, length);
    }

    if ((mbi->flags & MULTIBOOT_LOADER_MODULES) && (mbi->mods_count == 0)) {
        boot_raw_mbi.flags &= ~MULTIBOOT_LOADER_MODULES;
    }

    /*
     * The module command lines will be memory mapped later during
     * initialization. Their respective sizes must be saved.
     */
    boot_save_mod_cmdline_sizes(&boot_raw_mbi);
    boot_register_data(&boot_raw_mbi);
    biosmem_bootstrap(&boot_raw_mbi);
    return pmap_setup_paging();
}

void __init
boot_log_info(void)
{
    log_info(KERNEL_NAME "/" QUOTE(X15_X86_SUBARCH) " " KERNEL_VERSION
#ifdef X15_X86_PAE
             " PAE"
#endif /* X15_X86_PAE */
             );
}

static void * __init
boot_save_memory(uint32_t addr, size_t size)
{
    uintptr_t map_addr;
    size_t map_size;
    const void *src;
    void *copy;

    /*
     * Creates temporary virtual mappings because, on 32-bits systems,
     * there is no guarantee that the boot data will be available from
     * the direct physical mapping.
     */
    src = vm_kmem_map_pa(addr, size, &map_addr, &map_size);

    if (src == NULL) {
        panic("boot: unable to map boot data in kernel map");
    }

    copy = kmem_alloc(size);

    if (copy == NULL) {
        panic("boot: unable to allocate memory for boot data copy");
    }

    memcpy(copy, src, size);
    vm_kmem_unmap_pa(map_addr, map_size);
    return copy;
}

static void __init
boot_save_mod(struct multiboot_module *dest_mod,
              const struct multiboot_raw_module *src_mod)
{
    uintptr_t map_addr;
    size_t size, map_size;
    const void *src;
    void *copy;

    size = src_mod->mod_end - src_mod->mod_start;
    src = vm_kmem_map_pa(src_mod->mod_start, size, &map_addr, &map_size);

    if (src == NULL) {
        panic("boot: unable to map module in kernel map");
    }

    copy = kmem_alloc(size);

    if (copy == NULL) {
        panic("boot: unable to allocate memory for module copy");
    }

    memcpy(copy, src, size);
    vm_kmem_unmap_pa(map_addr, map_size);

    dest_mod->mod_start = copy;
    dest_mod->mod_end = copy + size;

    if (src_mod->string == 0) {
        dest_mod->string = NULL;
    } else {
        dest_mod->string = boot_save_memory(src_mod->string, src_mod->reserved);
    }
}

static void __init
boot_save_mods(void)
{
    const struct multiboot_raw_module *src;
    struct multiboot_module *dest;
    uintptr_t map_addr;
    size_t size, map_size;
    uint32_t i;

    if (!(boot_raw_mbi.flags & MULTIBOOT_LOADER_MODULES)) {
        boot_mbi.mods_addr = NULL;
        boot_mbi.mods_count = boot_raw_mbi.mods_count;
        return;
    }

    size = boot_raw_mbi.mods_count * sizeof(struct multiboot_raw_module);
    src = vm_kmem_map_pa(boot_raw_mbi.mods_addr, size, &map_addr, &map_size);

    if (src == NULL) {
        panic("boot: unable to map module table in kernel map");
    }

    size = boot_raw_mbi.mods_count * sizeof(struct multiboot_module);
    dest = kmem_alloc(size);

    if (dest == NULL) {
        panic("boot: unable to allocate memory for the module table");
    }

    for (i = 0; i < boot_raw_mbi.mods_count; i++) {
        boot_save_mod(&dest[i], &src[i]);
    }

    vm_kmem_unmap_pa(map_addr, map_size);

    boot_mbi.mods_addr = dest;
    boot_mbi.mods_count = boot_raw_mbi.mods_count;
}

/*
 * Copy boot data in kernel allocated memory.
 *
 * At this point, the only required boot data are the modules and the command
 * line strings. Optionally, the kernel can use the symbol table, if passed by
 * the boot loader. Once the boot data are managed as kernel buffers, their
 * backing pages can be freed.
 */
static int __init
boot_save_data(void)
{
    boot_mbi.flags = boot_raw_mbi.flags;
    boot_save_mods();
    return 0;
}

INIT_OP_DEFINE(boot_save_data,
               INIT_OP_DEP(kmem_setup, true),
               INIT_OP_DEP(panic_setup, true),
               INIT_OP_DEP(vm_kmem_setup, true));

void __init
boot_main(void)
{
    arg_set_cmdline(boot_tmp_cmdline);
    strace_set_mbi(&boot_raw_mbi);
    kernel_main();

    /* Never reached */
}

void __init
boot_ap_main(void)
{
    cpu_ap_setup();
    thread_ap_setup();
    pmap_ap_setup();
    kernel_ap_main();

    /* Never reached */
}

/*
 * Init operation aliases.
 */

static int __init
boot_bootstrap_console(void)
{
    return 0;
}

INIT_OP_DEFINE(boot_bootstrap_console,
               INIT_OP_DEP(atcons_bootstrap, true),
               INIT_OP_DEP(uart_bootstrap, true));

static int __init
boot_setup_console(void)
{
    return 0;
}

INIT_OP_DEFINE(boot_setup_console,
               INIT_OP_DEP(atcons_setup, true),
               INIT_OP_DEP(uart_setup, true));

static int __init
boot_load_vm_page_zones(void)
{
    return 0;
}

INIT_OP_DEFINE(boot_load_vm_page_zones,
               INIT_OP_DEP(biosmem_setup, true));

static int __init
boot_setup_intr(void)
{
    return 0;
}

INIT_OP_DEFINE(boot_setup_intr,
               INIT_OP_DEP(acpi_setup, true));

static int __init
boot_setup_shutdown(void)
{
    return 0;
}

INIT_OP_DEFINE(boot_setup_shutdown,
               INIT_OP_DEP(acpi_setup, true),
               INIT_OP_DEP(cpu_setup_shutdown, true));
