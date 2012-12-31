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

#ifndef _X86_ELF_H
#define _X86_ELF_H

#define ELF_SHT_SYMTAB  2
#define ELF_SHT_STRTAB  3

struct elf_shdr {
    unsigned int name;
    unsigned int type;
    unsigned int flags;
    unsigned long addr;
    unsigned long offset;
    unsigned int size;
    unsigned int link;
    unsigned int info;
    unsigned int addralign;
    unsigned int entsize;
};

#ifdef __LP64__

struct elf_sym {
    unsigned int name;
    unsigned char info;
    unsigned char other;
    unsigned short shndx;
    unsigned long value;
    unsigned long size;
};

#else /* __LP64__ */

struct elf_sym {
    unsigned int name;
    unsigned long value;
    unsigned long size;
    unsigned char info;
    unsigned char other;
    unsigned short shndx;
};

#endif /* __LP64__ */

#endif /* _X86_ELF_H */
