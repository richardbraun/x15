EXTRA_DIST =
MOSTLYCLEANFILES =
AM_CPPFLAGS =
AM_CFLAGS =
SUFFIXES =

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

SUFFIXES += .lds .lds.S

.lds.S.lds:
	$(AM_V_GEN)$(CPP) -P $(AM_CPPFLAGS) -o $@ $<

ASCIIDOC_FLAGS = -d manpage -a revnumber=@PACKAGE_VERSION@
A2X_FLAGS = -d manpage -a revnumber=@PACKAGE_VERSION@

SUFFIXES += .9 .9.html .9.xml .9.txt

.9.txt.9.html:
	$(AM_V_GEN)$(ASCIIDOC) $(ASCIIDOC_FLAGS) -b html5 -o $(abs_top_builddir)/$@ $<

# Expose intermediate DocBook files for correct parallel builds.
.9.txt.9.xml:
	$(AM_V_GEN)$(ASCIIDOC) $(ASCIIDOC_FLAGS) -b docbook -o $(abs_top_builddir)/$@ $<

.9.xml.9:
	$(AM_V_GEN)$(A2X) $(A2X_FLAGS) -f manpage --xsltproc-opts="-o $(abs_top_builddir)/$@" $<

exec_bootdir = /boot
exec_boot_PROGRAMS = x15
x15_DEPENDENCIES = arch/$(arch)/x15.lds
MOSTLYCLEANFILES += arch/$(arch)/x15.lds
x15_SOURCES =
x15_LDFLAGS = -nostdlib -Xlinker -T arch/$(arch)/x15.lds
x15_LDADD = -lgcc

include Makefrag.am
