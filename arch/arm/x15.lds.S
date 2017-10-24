/* OUTPUT_FORMAT("elf32-little") */
/* OUTPUT_ARCH(arm) */

ENTRY(_start)

#include <kern/init.h>
#include <machine/boot.h>
#include <machine/cpu.h>
#include <machine/page.h>
#include <machine/pmem.h>

PHDRS
{
    /* Flags are actually similar to classic Unix permissions */
    load    PT_LOAD FLAGS(7);
    boot    PT_LOAD FLAGS(7);
    init    PT_LOAD FLAGS(7);
    percpu  PT_LOAD FLAGS(6);
    text    PT_LOAD FLAGS(5);
    rodata  PT_LOAD FLAGS(4);
    data    PT_LOAD FLAGS(6);
}

SECTIONS
{
    . = 0;

    .boot.load : {
        *(BOOT_LOAD_SECTION)
    } : load

    . += PMEM_RAM_START;
    _boot = .;

    .boot ALIGN(PAGE_SIZE) : AT(BOOT_RTOL(ADDR(.boot))) {
        *(BOOT_TEXT_SECTION)
        *(BOOT_DATA_SECTION)
    } : boot

    . = ALIGN(PAGE_SIZE);
    _boot_end = .;

    . += (PMAP_START_KERNEL_ADDRESS - PMEM_RAM_START);
    _init = .;

    .init ALIGN(PAGE_SIZE) : AT(BOOT_VTOL(ADDR(.init))) {
        *(.init.text)
        *(.init.data)

        . = ALIGN(INIT_OP_ALIGN);
        _init_ops = .;
        *(.init.ops)
        _init_ops_end = .;

    } : init

    . = ALIGN(PAGE_SIZE);
    _init_end = .;
    _percpu = .;

    .percpu 0 : AT(BOOT_VTOL(_percpu)) {
        *(.percpu)
    } : percpu

    . = _percpu + SIZEOF(.percpu);
    . = ALIGN(PAGE_SIZE);
    _percpu_end = .;
    _text = .;

    .text ALIGN(PAGE_SIZE) : AT(BOOT_VTOL(ADDR(.text))) {
        *(.text)
    } : text

    . = ALIGN(PAGE_SIZE);
    _rodata = .;

    .rodata ALIGN(PAGE_SIZE) : AT(BOOT_VTOL(ADDR(.rodata))) {
        *(.rodata)
    } : rodata

    .notes ALIGN(CPU_DATA_ALIGN) : AT(BOOT_VTOL(ADDR(.notes))) {
        *(.note.*)
    } : rodata

    . = ALIGN(PAGE_SIZE);
    _data = .;

    .data ALIGN(PAGE_SIZE) : AT(BOOT_VTOL(ADDR(.data))) {
        . = ALIGN(CPU_L1_SIZE);
        *(.data.read_mostly)
        . = ALIGN(CPU_L1_SIZE);
        *(.data)
    } : data

    . = ALIGN(PAGE_SIZE);
    _bss = .;

    .bss ALIGN(CPU_DATA_ALIGN) : AT(BOOT_VTOL(ADDR(.bss))) {
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
