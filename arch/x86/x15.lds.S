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

#include <kern/param.h>
#include <machine/boot.h>

PHDRS
{
    boot    PT_LOAD FLAGS(7);
    init    PT_LOAD FLAGS(7);
    text    PT_LOAD FLAGS(5);
    rodata  PT_LOAD FLAGS(4);
    data    PT_LOAD FLAGS(6);
}

SECTIONS
{
    . = BOOT_OFFSET;

    .boot ALIGN(PAGE_SIZE): {
        _boot = .;
        *(.boothdr)
        *(.boot)
        *(.bootdata)
        _eboot = .;
    } : boot

    . += KERNEL_OFFSET;

    .init ALIGN(PAGE_SIZE): AT(ADDR(.init) - KERNEL_OFFSET) {
        _init = .;
        *(.init)
        _einit = .;
    } : init

    .initrodata ALIGN(8): AT(ADDR(.initrodata) - KERNEL_OFFSET) {
        _initrodata = .;
        *(.initrodata)
        _einitrodata = .;
    } : init

    .initdata ALIGN(8): AT(ADDR(.initdata) - KERNEL_OFFSET) {
        _initdata = .;
        *(.initdata)
        _einitdata = .;
    } : init

    .text ALIGN(PAGE_SIZE): AT(ADDR(.text) - KERNEL_OFFSET) {
        _text = .;
        *(.text)
        _etext = .;
    } : text

    .rodata ALIGN(PAGE_SIZE): AT(ADDR(.rodata) - KERNEL_OFFSET) {
        _rodata = .;
        *(.rodata)
        _erodata = .;
    } : rodata

    .notes ALIGN(8): AT(ADDR(.notes) - KERNEL_OFFSET) {
        _notes = .;
        *(.note.*)
        _enotes = .;
    } : rodata

    .data ALIGN(PAGE_SIZE): AT(ADDR(.data) - KERNEL_OFFSET) {
        _data = .;
        *(.data)
        _edata = .;
    } : data

    .bss ALIGN(8): AT(ADDR(.bss) - KERNEL_OFFSET) {
        _bss = .;
        *(.bss)
        *(COMMON)
        . = ALIGN(PAGE_SIZE);
        _ebss = .;
    } : data

    _end = .;
}
