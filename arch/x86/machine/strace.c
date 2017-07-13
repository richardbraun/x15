/*
 * Copyright (c) 2012-2014 Richard Braun.
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

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <kern/init.h>
#include <kern/kmem.h>
#include <kern/log.h>
#include <kern/macros.h>
#include <machine/elf.h>
#include <machine/multiboot.h>
#include <machine/pmap.h>
#include <machine/strace.h>
#include <machine/types.h>
#include <vm/vm_kmem.h>

#ifdef __LP64__
#define STRACE_ADDR_FORMAT "%#018lx"
#else /* __LP64__ */
#define STRACE_ADDR_FORMAT "%#010lx"
#endif /* __LP64__ */

static const struct multiboot_raw_info *strace_mbi __initdata;

static struct elf_sym *strace_symtab __read_mostly;
static struct elf_sym *strace_symtab_end __read_mostly;
static char *strace_strtab __read_mostly;

static const char *
strace_lookup(uintptr_t addr, uintptr_t *offset, uintptr_t *size)
{
    struct elf_sym *sym;

    for (sym = strace_symtab; sym < strace_symtab_end; sym++) {
        if ((sym->size != 0)
            && (addr >= sym->value)
            && (addr <= (sym->value + sym->size))) {
            break;
        }
    }

    if (sym >= strace_symtab_end) {
        return NULL;
    }

    if (sym->name == 0) {
        return NULL;
    }

    *offset = addr - sym->value;
    *size = sym->size;
    return &strace_strtab[sym->name];
}

static void
strace_show_one(unsigned int index, unsigned long ip)
{
    uintptr_t offset, size;
    const char *name;

    name = strace_lookup(ip, &offset, &size);

    if (name == NULL) {
        printf("#%u [" STRACE_ADDR_FORMAT "]\n", index, ip);
    } else {
        printf("#%u [" STRACE_ADDR_FORMAT "] %s+%#lx/%#lx\n",
               index, ip, name, (unsigned long)offset, (unsigned long)size);
    }
}

void
strace_show(unsigned long ip, unsigned long bp)
{
    phys_addr_t pa;
    void **frame;
    unsigned int i;
    int error;

    strace_show_one(0, ip);

    i = 1;
    frame = (void **)bp;

    for (;;) {
        if (frame == NULL) {
            break;
        }

        error = pmap_kextract((uintptr_t)&frame[1], &pa);

        if (error) {
            printf("strace: unmapped return address at %p\n", &frame[1]);
            break;
        }

        strace_show_one(i, (unsigned long)frame[1]);
        error = pmap_kextract((uintptr_t)frame, &pa);

        if (error) {
            printf("strace: unmapped frame address at %p\n", frame);
            break;
        }

        i++;
        frame = frame[0];
    }
}

static void * __init
strace_copy_section(const struct elf_shdr *shdr)
{
    uintptr_t map_addr;
    size_t map_size;
    const void *src;
    void *copy;

    src = vm_kmem_map_pa(shdr->addr, shdr->size, &map_addr, &map_size);

    if (src == NULL) {
        log_err("strace: unable to map section");
        goto error_map;
    }

    copy = kmem_alloc(shdr->size);

    if (copy == NULL) {
        log_err("strace: unable to allocate section copy");
        goto error_copy;
    }

    memcpy(copy, src, shdr->size);
    vm_kmem_unmap_pa(map_addr, map_size);
    return copy;

error_copy:
    vm_kmem_unmap_pa(map_addr, map_size);
error_map:
    return NULL;
}

static const struct elf_shdr * __init
strace_lookup_section(const struct multiboot_raw_info *mbi, const void *table,
                      const char *shstrtab, const char *name)
{
    const struct elf_shdr *shdr;
    unsigned int i;
    const char *shdr_name;

    for (i = 0; i < mbi->shdr_num; i++) {
        shdr = table + (i * mbi->shdr_size);
        shdr_name = &shstrtab[shdr->name];

        if (strcmp(shdr_name, name) == 0) {
            return shdr;
        }
    }

    return NULL;
}

void __init
strace_set_mbi(const struct multiboot_raw_info *mbi)
{
    strace_mbi = mbi;
}

static int __init
strace_setup(void)
{
    const struct elf_shdr *shstrtab_hdr, *symtab_hdr, *strtab_hdr;
    const struct multiboot_raw_info *mbi;
    uintptr_t map_addr, shstrtab_map_addr;
    size_t size, map_size, shstrtab_map_size;
    const char *shstrtab;
    const void *table;

    mbi = strace_mbi;

    if (!(mbi->flags & MULTIBOOT_LOADER_SHDR) || (mbi->shdr_num == 0)) {
        goto no_syms;
    }

    size = mbi->shdr_num * mbi->shdr_size;
    table = vm_kmem_map_pa(mbi->shdr_addr, size, &map_addr, &map_size);

    if (table == NULL) {
        log_err("strace: unable to map section headers table");
        goto no_syms;
    }

    if (mbi->shdr_strndx >= mbi->shdr_num) {
        log_err("strace: invalid section names index");
        goto error_shstrndx;
    }

    shstrtab_hdr = table + (mbi->shdr_strndx * mbi->shdr_size);
    shstrtab = vm_kmem_map_pa(shstrtab_hdr->addr, shstrtab_hdr->size,
                              &shstrtab_map_addr, &shstrtab_map_size);

    if (shstrtab == NULL) {
        log_err("strace: unable to map section names");
        goto error_shstrtab;
    }

    symtab_hdr = strace_lookup_section(mbi, table, shstrtab, ".symtab");

    if (symtab_hdr == NULL) {
        log_err("strace: unable to find symbol table");
        goto error_symtab_lookup;
    }

    strtab_hdr = strace_lookup_section(mbi, table, shstrtab, ".strtab");

    if (strtab_hdr == NULL) {
        log_err("strace: unable to find symbol string table");
        goto error_strtab_lookup;
    }

    strace_symtab = strace_copy_section(symtab_hdr);

    if (strace_symtab == NULL) {
        goto error_symtab;
    }

    strace_symtab_end = (void *)strace_symtab + symtab_hdr->size;
    strace_strtab = strace_copy_section(strtab_hdr);

    if (strace_strtab == NULL) {
        goto error_strtab;
    }

    vm_kmem_unmap_pa(shstrtab_map_addr, shstrtab_map_size);
    vm_kmem_unmap_pa(map_addr, map_size);
    return 0;

error_strtab:
    kmem_free(strace_symtab, symtab_hdr->size);
error_symtab:
error_strtab_lookup:
error_symtab_lookup:
    vm_kmem_unmap_pa(shstrtab_map_addr, shstrtab_map_size);
error_shstrtab:
error_shstrndx:
    vm_kmem_unmap_pa(map_addr, map_size);
no_syms:
    strace_symtab = NULL;
    strace_symtab_end = NULL;
    strace_strtab = NULL;
    return 0;
}

INIT_OP_DEFINE(strace_setup,
               INIT_OP_DEP(kmem_setup, true),
               INIT_OP_DEP(log_setup, true),
               INIT_OP_DEP(pmap_bootstrap, true),
               INIT_OP_DEP(printf_setup, true),
               INIT_OP_DEP(vm_kmem_setup, true));
