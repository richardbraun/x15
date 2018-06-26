SHELL := /bin/sh

MAKEFLAGS += -rR
MAKEFLAGS += --no-print-directory

.PHONY: all
all: x15 docs

VERSION = 0.1
export VERSION

COMMA := ,

ifndef V
V := 0
endif

# Use callable variables so that commands can be split into multiple
# lines, but produce a single line when echoed. This makes copying
# commands easy. It also makes them somewhat self-describing.

ifeq ($(V),0)
Q := @

# $(call xbuild_action_print,<action_short_name>,<target>)
define xbuild_action_print
@printf "  %-7s %s\n" $(1) $(2)
@
endef
else ifneq ($(V),1)
$(error invalid value for V)
endif

export Q

# $(call xbuild_action_mkdir,<target>)
define xbuild_action_mkdir
	$(Q)mkdir -p $(dir $(1))
endef

# $(call xbuild_action,<action>,<target>)
define xbuild_action
	$(call xbuild_action_mkdir,$(2))
	$(call xbuild_action_print,$(1),$(2))
endef

define xbuild_kconfig_invoke
	$(Q)$(MAKE) -f $(SRCDIR)/$(KCONFIG_PATH)/Makefile $@
endef

define xbuild_gen_autoconf_h
	$(call xbuild_action,GEN,$@)cat $< \
		| sed -e 's/^\([^#]\)/#define \1/g' \
		      -e 's/=/ /' \
		| grep '^#define' > $@
endef

# $(call xbuild_check_cc_option,<option>)
define xbuild_check_cc_option
$(shell printf "int main(void){ return 0; }\n" \
        | $(CC) -Wall -Werror -x c $(1) -c - -o /dev/null 2> /dev/null \
        && printf -- "%s" $(1))
endef

# $(call xbuild_replace_source_suffix,<suffix>,<file_names>)
define xbuild_replace_source_suffix
$(sort $(patsubst %.c,%.$(1),$(filter %.c,$(2))) \
       $(patsubst %.S,%.$(1),$(filter %.S,$(2))))
endef

define xbuild_compile
	$(call xbuild_action,CC,$@) \
		$(COMPILE) -MMD -MP -c -o $@ $<
endef

define xbuild_gen_linker_script
	$(call xbuild_action,LDS,$@) \
		$(CPP) $(XBUILD_CPPFLAGS) -MMD -MP \
		-MF $@.d -MT $@ -P -o $@ $<
endef

# $(call xbuild_link,<objects>)
define xbuild_link
	$(call xbuild_action,LD,$@) \
		$(COMPILE) -o $@ $(1) $(XBUILD_LDFLAGS)
endef

define xbuild_clean
	$(Q)rm -f x15 \
	$(x15_OBJDEPS) \
	$(x15_OBJECTS) \
	$(x15_LDS)
endef

define xbuild_distclean
	$(clean)
	$(Q)rm -f .config \
	.config.old \
	include/generated/autoconf.h \
	include/generated/autoconf.mk
endef

ARCH ?= $(shell uname -m | sed -e s/i.86/x86/ -e s/x86_64/x86/ )
export ARCH

SRCDIR := $(realpath $(dir $(realpath $(firstword $(MAKEFILE_LIST)))))
VPATH := $(SRCDIR)
export SRCDIR VPATH

PREFIX ?= /usr/local
DATAROOTDIR ?= share

# Do not use MAKEFILE_LIST as its value is updated only on inclusion,
# which makes it unsuitable as a rule dependency in most of the file.
#
# These additional Makefiles are included in order.
MAKEFILE_INCLUDES := \
        $(SRCDIR)/arch/$(ARCH)/Makefile \
        $(SRCDIR)/doc/Makefile \
        $(SRCDIR)/kern/Makefile \
        $(SRCDIR)/test/Makefile \
        $(SRCDIR)/vm/Makefile
ALL_MAKEFILES := $(MAKEFILE_LIST) $(MAKEFILE_INCLUDES)

ifeq ($(words $(MAKECMDGOALS)),0)
else ifeq ($(words $(MAKECMDGOALS)),1)
else
$(error up to one target may be given)
endif

KCONFIG_PATH := tools/kconfig

# Export to Kconfig
export KCONFIG_PATH

HOSTCC := $(if $(shell type gcc 2>/dev/null),gcc,cc)
HOSTCXX = g++
HOSTCFLAGS := -g
HOSTCXXFLAGS := -g

# Export to Kconfig
export HOSTCC HOSTCXX HOSTCFLAGS HOSTCXXFLAGS

BOARDS := $(wildcard $(SRCDIR)/arch/$(ARCH)/configs/*_defconfig)
BOARDS := $(sort $(notdir $(BOARDS)))

.PHONY: help
help:
	@printf 'Configuration targets:\n'
	@$(Q)$(MAKE) -f $(SRCDIR)/$(KCONFIG_PATH)/Makefile $@
	@printf '\n'
	@printf 'Cleaning targets:\n'
	@printf '  clean                    - Remove most generated files but keep configuration\n'
	@printf '  distclean                - Remove all generated files\n'
	@printf '\n'
	@printf 'Build targets:\n'
	@printf '  all                      - Build all targets marked with [*]\n'
	@printf '* x15                      - Build the kernel ELF image\n'
	@printf '\n'
	@printf 'Documentation targets:\n'
	@printf '* docs                     - Build all documentation\n'
	$(DOC_HELP)
	@printf '\n'
	@printf 'Installation targets:\n'
	@printf '  install                  - Install the kernel and documentation\n'
	@printf '  install-strip            - Same as install but also strip the kernel\n'
	@printf '  install-x15              - Install the kernel only\n'
	@printf '  install-strip-x15        - Same as install-x15 but also strip the kernel\n'
	@printf '  install-docs             - Install documentation files\n'
	$(DOC_INSTALL_HELP)
	@printf '\n'
	@printf 'Architecture specific targets ($(ARCH)):\n'
	@$(if $(BOARDS), \
		$(foreach b, $(BOARDS), \
		printf "  %-24s - Build for %s\\n" $(b) $(subst _defconfig,,$(b));))
	@printf '\n'
	@printf 'Options:\n'
	@printf '  make V=0                 - Quiet build\n'
	@printf '  make V=1                 - Verbose build\n'
	@printf '\n'
	@printf 'Notes:\n'
	@printf '- One target at most may be specified.\n'
	@printf '- The compiler program and flags may be given at configuration time\n'
	@printf '  through the CC and CFLAGS variables respectively.\n'
	@printf '- Out-of-tree builds are performed with the following command:\n'
	@printf '    make -f path/to/src/Makefile [options] [target]\n'
	@printf '- The source directory must be completely clean for reliable out-of-tree builds.\n'
	@printf '- Use the DESTDIR and PREFIX variables to control installation, e.g.:\n'
	@printf '    make DESTDIR=/stagingroot PREFIX=/usr install\n'
	@printf '\n'
	@printf 'See README for more information.\n'

# Don't create a %config pattern rule as it would conflict with .config
KCONFIG_TARGETS := config nconfig menuconfig xconfig gconfig \
                   allnoconfig allyesconfig alldefconfig randconfig \
                   oldconfig olddefconfig defconfig savedefconfig \
                   listnewconfig

.PHONY: $(KCONFIG_TARGETS)
$(KCONFIG_TARGETS):
	$(call xbuild_kconfig_invoke)

%_defconfig:
	$(call xbuild_kconfig_invoke)

include/generated/autoconf.h: .config $(ALL_MAKEFILES)
	$(call xbuild_gen_autoconf_h)

-include .config

ifdef CONFIG_COMPILER
# Use printf to remove quotes
CC := $(shell printf -- $(CONFIG_COMPILER))
else
CC := gcc
endif

# The CC variable is used by Kconfig to set the value of CONFIG_COMPILER.
export CC

TOOLCHAIN_NAME = $(shell printf "%s" $(CC) | rev | cut -s -d - -f 2- | rev)

ifneq ($(TOOLCHAIN_NAME),)
TOOLCHAIN_PREFIX = $(TOOLCHAIN_NAME)-
endif

CPP := $(CC) -E

CFLAGS ?= -O2 -g

# Export to CONFIG_CFLAGS
export CFLAGS

XBUILD_CPPFLAGS :=
XBUILD_CFLAGS :=

XBUILD_CPPFLAGS += -pipe

# Do not include headers from the hosted environment, but
# do include headers from the compiler.
XBUILD_CPPFLAGS += -nostdinc
XBUILD_CPPFLAGS += -isystem $(shell $(CC) -print-file-name=include)

XBUILD_CPPFLAGS += -std=gnu11
XBUILD_CPPFLAGS += -ffreestanding
XBUILD_CPPFLAGS += -include $(SRCDIR)/kern/config.h
XBUILD_CPPFLAGS += -include include/generated/autoconf.h
XBUILD_CPPFLAGS += -I$(SRCDIR)
XBUILD_CPPFLAGS += -I$(SRCDIR)/include
XBUILD_CPPFLAGS += -I$(SRCDIR)/arch/$(ARCH)

ifndef CONFIG_ASSERT
XBUILD_CPPFLAGS += -DNDEBUG
endif

XBUILD_CFLAGS += -fsigned-char
XBUILD_CFLAGS += -fno-common

# XXX Some assemblers consider the / symbol to denote comments. The --divide
# option suppresses that behavior.
XBUILD_CFLAGS += $(call xbuild_check_cc_option,-Wa$(COMMA)--divide)

XBUILD_CFLAGS += -Wall
XBUILD_CFLAGS += -Wextra
XBUILD_CFLAGS += -Wshadow
XBUILD_CFLAGS += -Wmissing-prototypes
XBUILD_CFLAGS += -Wstrict-prototypes

# XXX Temporary, until a single solution is adopted to silence these warnings.
XBUILD_CFLAGS += -Wno-unneeded-internal-declaration

XBUILD_CFLAGS += $(call xbuild_check_cc_option,-fno-PIE)
XBUILD_CFLAGS += $(call xbuild_check_cc_option,-Qunused-arguments)

XBUILD_LDFLAGS += -static -nostdlib

# Disable the build ID feature of the linker
XBUILD_LDFLAGS += -Wl,--build-id=none

x15_SOURCES-y :=
x15_LDS_S := arch/$(ARCH)/x15.lds.S

# Include the additional Makefiles here, as they may augment the build
# variables.
include $(MAKEFILE_INCLUDES)

# Export to Kconfig.
# Must be defined by the architecture-specific Makefile.
export KCONFIG_DEFCONFIG

ifdef CONFIG_COMPILER_OPTIONS
# Use printf to remove quotes
XBUILD_CFLAGS += $(shell printf -- $(CONFIG_COMPILER_OPTIONS))
endif

COMPILE := $(CC) $(XBUILD_CPPFLAGS) $(XBUILD_CFLAGS)

# Don't change preprocessor and compiler flags from this point

x15_SOURCES := $(x15_SOURCES-y)
x15_OBJDEPS := $(call xbuild_replace_source_suffix,d,$(x15_SOURCES))
x15_OBJECTS := $(call xbuild_replace_source_suffix,o,$(x15_SOURCES))
x15_LDS := $(basename $(x15_LDS_S))
x15_LDS_D := $(x15_LDS).d

XBUILD_LDFLAGS += -Wl,--script=$(x15_LDS)

define gen_sorted_init_ops
	$(call xbuild_action,GEN,$@) \
		$(SRCDIR)/tools/tsort_init_ops.sh "$(COMPILE)" "$@" $^
endef

.INTERMEDIATE: .x15.sorted_init_ops
.x15.sorted_init_ops: $(filter %.c,$(x15_SOURCES)) include/generated/autoconf.h
	$(call gen_sorted_init_ops)

x15_DEPS := $(x15_LDS) .x15.sorted_init_ops

# Compiling produces dependency rules as a side-effect. When the dependency
# rules file doesn't exist, the main source file is enough to trigger a
# rebuild. Afterwards, the dependency rules file is included here and the
# rules provide correct incremental compilation.
-include $(x15_OBJDEPS) $(x15_LDS_D)

%.o: %.c include/generated/autoconf.h
	$(xbuild_compile)

%.o: %.S include/generated/autoconf.h
	$(xbuild_compile)

%.lds: %.lds.S include/generated/autoconf.h
	$(xbuild_gen_linker_script)

x15: $(x15_OBJECTS) $(x15_DEPS)
	$(call xbuild_link,$(x15_OBJECTS))

.PHONY: install-x15
install-x15:
	install -D -m 644 x15 $(DESTDIR)/boot/x15

.PHONY: install-strip-x15
install-strip-x15:
	install -s -D -m 644 x15 $(DESTDIR)/boot/x15

.PHONY: install
install: install-x15 install-docs

.PHONY: install-strip
install-strip: install-strip-x15 install-docs

.PHONY: clean
clean: clean-docs
	$(Q)$(MAKE) -f $(SRCDIR)/$(KCONFIG_PATH)/Makefile $@
	$(call xbuild_clean)

.PHONY: distclean
distclean: clean distclean-docs
	$(Q)$(MAKE) -f $(SRCDIR)/$(KCONFIG_PATH)/Makefile $@
	$(call xbuild_distclean)
