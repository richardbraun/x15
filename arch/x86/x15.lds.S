#ifdef __LP64__
OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
#else
OUTPUT_FORMAT("elf32-i386")
OUTPUT_ARCH(i386)
#endif /* __LP64__ */

ENTRY(_start)

#include <machine/boot.h>
#include <machine/param.h>

PHDRS
{
    /* Flags are actually similar to classic Unix permissions */
    boot    PT_LOAD FLAGS(7);
    init    PT_LOAD FLAGS(7);
    percpu  PT_LOAD FLAGS(6);
    text    PT_LOAD FLAGS(5);
    rodata  PT_LOAD FLAGS(4);
    data    PT_LOAD FLAGS(6);
}

SECTIONS
{
    . = BOOT_OFFSET;
    _boot = .;

    .boot ALIGN(PAGE_SIZE) : {
        *(.boot.hdr)
        *(.boot.text)
        *(.boot.data)
    } : boot

    . = ALIGN(PAGE_SIZE);
    _boot_end = .;

    . += VM_KERNEL_OFFSET;
    _init = .;

    .init ALIGN(PAGE_SIZE) : AT(BOOT_VTOP(ADDR(.init))) {
        *(.init.text)
        *(.init.data)
    } : init

    . = ALIGN(PAGE_SIZE);
    _init_end = .;
    _percpu = .;

    .percpu 0 : AT(BOOT_VTOP(_percpu)) {
        *(.percpu)
    } : percpu

    . = _percpu + SIZEOF(.percpu);
    . = ALIGN(PAGE_SIZE);
    _percpu_end = .;
    _text = .;

    .text ALIGN(PAGE_SIZE) : AT(BOOT_VTOP(ADDR(.text))) {
        *(.text)
    } : text

    . = ALIGN(PAGE_SIZE);
    _rodata = .;

    .rodata ALIGN(PAGE_SIZE) : AT(BOOT_VTOP(ADDR(.rodata))) {
        *(.rodata)
    } : rodata

    .notes ALIGN(DATA_ALIGN) : AT(BOOT_VTOP(ADDR(.notes))) {
        *(.note.*)
    } : rodata

    . = ALIGN(PAGE_SIZE);
    _data = .;

    .data ALIGN(PAGE_SIZE) : AT(BOOT_VTOP(ADDR(.data))) {
        . = ALIGN(CPU_L1_SIZE);
        *(.data.read_mostly)
        . = ALIGN(CPU_L1_SIZE);
        *(.data)
    } : data

    .bss ALIGN(DATA_ALIGN) : AT(BOOT_VTOP(ADDR(.bss))) {
        *(.bss)
    } : data

    . = ALIGN(PAGE_SIZE);
    _end = .;

    /*
     * XXX A global offset section is created because of linking with libgcc.
     * Is it safe to discard it ?
     */
    /DISCARD/ : {
        *(.eh_frame)
    }
}
