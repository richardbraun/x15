KCONFIG_DEFCONFIG := qemu_virt_defconfig

XBUILD_CFLAGS += -mcpu=cortex-a15
XBUILD_CFLAGS += -fdelete-null-pointer-checks

x15_SOURCES-y += \
        arch/arm/machine/boot_asm.S \
        arch/arm/machine/boot.c \
        arch/arm/machine/cpu.c \
        arch/arm/machine/pmap.c \
        arch/arm/machine/strace.c \
        arch/arm/machine/tcb_asm.S \
        arch/arm/machine/tcb.c
