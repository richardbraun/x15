ifeq ($(shell uname -m),x86_64)
  KCONFIG_DEFCONFIG := amd64_defconfig
else
  KCONFIG_DEFCONFIG := i386_defconfig
endif

# Prevent GCC from generating any FP code by mistake.
XBUILD_CFLAGS += -mno-sse -mno-mmx -mno-sse2 -mno-3dnow
XBUILD_CFLAGS += $(call cc-option,-mno-avx,)

# Store unwind information in .debug_frame instead of .eh_frame. Unwind
# tables aren't used at runtime, so using a debug section reduces the kernel
# code size.
XBUILD_CFLAGS += -fno-asynchronous-unwind-tables

# For now, use frame pointers for convenient stack tracing.
XBUILD_CFLAGS += -fno-omit-frame-pointer

XBUILD_LDFLAGS += -Wl,-z,max-page-size=4096 -Wl,-z,common-page-size=4096

ifeq ($(CONFIG_X86_32),y)
        biarch := $(call cc-option,-m32)

        XBUILD_CPPFLAGS += -m32

        XBUILD_LDFLAGS += -lgcc
else
        biarch := -m64

        XBUILD_CPPFLAGS += -m64

        # XXX The kernel isn't linked with libgcc on amd64, because libgcc
        # uses red zones. But since there are actually very few functions
        # provided by libgcc on amd64, it was decided to just not link with
        # it. If it turns out that libgcc is really needed some day, the
        # kernel can somewhat easily be changed to support red zones.
        XBUILD_CFLAGS += -mno-red-zone
        XBUILD_CFLAGS += -mcmodel=kernel
endif

x15_SOURCES-y += \
        arch/x86/machine/acpi.c \
        arch/x86/machine/atcons.c \
        arch/x86/machine/atkbd.c \
        arch/x86/machine/biosmem.c \
        arch/x86/machine/boot_asm.S \
        arch/x86/machine/boot.c \
        arch/x86/machine/cga.c \
        arch/x86/machine/cpu_asm.S \
        arch/x86/machine/cpu.c \
        arch/x86/machine/ioapic.c \
        arch/x86/machine/lapic.c \
        arch/x86/machine/pic.c \
        arch/x86/machine/pit.c \
        arch/x86/machine/pmap.c \
        arch/x86/machine/ssp.c \
        arch/x86/machine/strace.c \
        arch/x86/machine/string.c \
        arch/x86/machine/tcb_asm.S \
        arch/x86/machine/tcb.c \
        arch/x86/machine/trap_asm.S \
        arch/x86/machine/trap.c \
        arch/x86/machine/uart.c
