EXTRA_DIST =
MOSTLYCLEANFILES =

AM_CPPFLAGS = \
	-pipe \
	-std=gnu99 \
	-imacros config.h \
	-I$(top_srcdir) \
	-I$(top_srcdir)/arch/$(arch)

AM_CFLAGS = \
	-Wall \
	-Wextra \
	-Wshadow \
	-Wmissing-prototypes \
	-Wstrict-prototypes \
	-fsigned-char \
	-ffreestanding \
	-fno-common \
	-fno-stack-protector

LDS_V = $(LDS_V_$(V))
LDS_V_ = $(LDS_V_$(AM_DEFAULT_VERBOSITY))
LDS_V_0 = @echo "  LDS    $@";

SUFFIXES = .lds .lds.S

.lds.S.lds:
	$(LDS_V) $(CPP) -P $(AM_CPPFLAGS) -o $@ $<

exec_bootdir = $(exec_prefix)/boot
exec_boot_PROGRAMS = x15
x15_DEPENDENCIES = arch/$(arch)/x15.lds
MOSTLYCLEANFILES += arch/$(arch)/x15.lds
x15_SOURCES =
x15_LDFLAGS = -nostdlib -Xlinker -T arch/$(arch)/x15.lds
x15_LDADD = -lgcc

include Makefrag.am
