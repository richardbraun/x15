EXTRA_DIST =
MOSTLYCLEANFILES =
AM_CPPFLAGS =
AM_CFLAGS =

AM_CPPFLAGS += -pipe
AM_CPPFLAGS += -imacros config.h

# Do not include headers from the hosted environment, but
# do include headers from the compiler.
AM_CPPFLAGS += -nostdinc
AM_CPPFLAGS += -isystem $(shell $(CC) -print-file-name=include)

AM_CPPFLAGS += \
	-I$(top_srcdir) \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/arch/$(arch)

AM_CFLAGS += -ffreestanding

AM_CFLAGS += -std=gnu11

AM_CFLAGS += \
	-Wall \
	-Wextra \
	-Wshadow \
	-Wmissing-prototypes \
	-Wstrict-prototypes

AM_CFLAGS += \
	-fsigned-char \
	-fno-common

# TODO Add stack protector support
AM_CFLAGS += -fno-stack-protector

AM_CFLAGS += -nostdlib

SUFFIXES = .lds .lds.S

.lds.S.lds:
	$(AM_V_GEN)$(CPP) -P $(AM_CPPFLAGS) -o $@ $<

exec_bootdir = $(exec_prefix)/boot
exec_boot_PROGRAMS = x15
x15_DEPENDENCIES = arch/$(arch)/x15.lds
MOSTLYCLEANFILES += arch/$(arch)/x15.lds
x15_SOURCES =
x15_LDFLAGS = -nostdlib -Xlinker -T arch/$(arch)/x15.lds
x15_LDADD = -lgcc

include Makefrag.am
