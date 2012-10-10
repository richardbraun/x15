/* Don't replace i386 */
#undef i386

#ifdef __LP64__
OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
#else
OUTPUT_FORMAT("elf32-i386")
OUTPUT_ARCH(i386)
#endif /* __LP64__ */

ENTRY(_start)

#define __ASSEMBLY__

#include <machine/boot.h>
#include <machine/param.h>

PHDRS
{
    /* Flags are actually similar to classic Unix permissions */
    init    PT_LOAD FLAGS(7);
    text    PT_LOAD FLAGS(5);
    rodata  PT_LOAD FLAGS(4);
    data    PT_LOAD FLAGS(6);
}

SECTIONS
{
    . = BOOT_OFFSET;
    _init = .;

    .init ALIGN(PAGE_SIZE): {
        *(.init.hdr)
        *(.init.text)
        *(.init.data)
    } : init

    . = ALIGN(PAGE_SIZE);
    _einit = .;

    . += KERNEL_OFFSET;
    _text = .;

    .text ALIGN(PAGE_SIZE): AT(ADDR(.text) - KERNEL_OFFSET) {
        *(.text)
    } : text

    . = ALIGN(PAGE_SIZE);
    _rodata = .;

    .rodata ALIGN(PAGE_SIZE): AT(ADDR(.rodata) - KERNEL_OFFSET) {
        *(.rodata)
    } : rodata

    .notes ALIGN(8): AT(ADDR(.notes) - KERNEL_OFFSET) {
        *(.note.*)
    } : rodata

    . = ALIGN(PAGE_SIZE);
    _data = .;

    .data ALIGN(PAGE_SIZE): AT(ADDR(.data) - KERNEL_OFFSET) {
        *(.data)
    } : data

    .bss ALIGN(8): AT(ADDR(.bss) - KERNEL_OFFSET) {
        *(.bss)
        *(COMMON)
    } : data

    . = ALIGN(PAGE_SIZE);
    _end = .;
}
