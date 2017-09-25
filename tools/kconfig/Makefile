# ===========================================================================
# Kernel configuration targets
# These targets are used from top-level makefile

PHONY += xconfig gconfig menuconfig config

# We need this, in case the user has it in its environment
unexport CONFIG_

ifneq ($(Q),)
# $(call kconfig_action,<action>,<target>)
define kconfig_action
@printf "  %-7s %s\n" $(1) $(2)
@
endef
endif

srctree := $(SRCDIR)
obj := $(KCONFIG_PATH)
src := $(obj)
kecho := echo

# This environment variable is used by the conf tools to locate Kconfig files.
export srctree

Kconfig := $(srctree)/Kconfig

xconfig: $(obj)/qconf
	$< $(Kconfig)

gconfig: $(obj)/gconf
	$< $(Kconfig)

menuconfig: $(obj)/mconf
	$< $(Kconfig)

config: $(obj)/conf
	$< --oldaskconfig $(Kconfig)

nconfig: $(obj)/nconf
	$< $(Kconfig)

# These targets map 1:1 to the commandline options of 'conf'
simple-targets := oldconfig allnoconfig allyesconfig \
	alldefconfig randconfig listnewconfig olddefconfig
PHONY += $(simple-targets)

$(simple-targets): $(obj)/conf
	$< --$@ $(Kconfig)

PHONY += savedefconfig defconfig

savedefconfig: $(obj)/conf
	$< --$@=defconfig $(Kconfig)

defconfig: $(obj)/conf
	@$(kecho) "*** Default configuration is based on '$(KCONFIG_DEFCONFIG)'"
	$(Q)$< --defconfig=arch/$(ARCH)/configs/$(KCONFIG_DEFCONFIG) $(Kconfig)

%_defconfig: $(obj)/conf
	$(Q)$< --defconfig=arch/$(ARCH)/configs/$@ $(Kconfig)

# Help text used by make help
help:
	@echo  '  config                   - Set configuration - line-oriented program'
	@echo  '  nconfig                  - Set configuration - ncurses menu based program'
	@echo  '  menuconfig               - Set configuration - menu based program'
	@echo  '  xconfig                  - Set configuration - Qt based front-end'
	@echo  '  gconfig                  - Set configuration - GTK+ based front-end'
	@echo  '  allnoconfig              - New configuration - all options disabled'
	@echo  '  allyesconfig             - New configuration - all options enabled'
	@echo  '  alldefconfig             - New configuration - default values'
	@echo  '  randconfig               - New configuration - random values'
	@echo  '  oldconfig                - Reuse existing .config for configuration'
	@echo  '  olddefconfig             - Same as oldconfig but sets new symbols to their'
	@echo  '                             default value'
	@echo  '  defconfig                - Default architecture-specific configuration'
	@echo  '  savedefconfig            - Save configuration as ./defconfig (minimal config)'
	@echo  '  listnewconfig            - List new options'

# lxdialog stuff
check-lxdialog  := $(srctree)/$(src)/lxdialog/check-lxdialog.sh

# Use recursively expanded variables so we do not call gcc unless
# we really need to do so. (Do not call gcc as part of make mrproper)
HOST_EXTRACFLAGS += $(shell $(CONFIG_HOST_SHELL) $(check-lxdialog) -ccflags) \
                    -DLOCALE

# ===========================================================================
# Shared Makefile for the various kconfig executables:
# conf:	  Used for defconfig, oldconfig and related targets
# nconf:  Used for the nconfig target.
#         Utilizes ncurses
# mconf:  Used for the menuconfig target
#         Utilizes the lxdialog package
# qconf:  Used for the xconfig target
#         Based on Qt which needs to be installed to compile it
# gconf:  Used for the gconfig target
#         Based on GTK+ which needs to be installed to compile it
# object files used by all kconfig flavours

lxdialog := lxdialog/checklist.o lxdialog/util.o lxdialog/inputbox.o
lxdialog += lxdialog/textbox.o lxdialog/yesno.o lxdialog/menubox.o

conf-objs	:= conf.o  zconf.tab.o
mconf-objs     := mconf.o zconf.tab.o $(lxdialog)
nconf-objs     := nconf.o zconf.tab.o nconf.gui.o
qconf-cxxobjs	:= qconf.o
qconf-objs	:= zconf.tab.o
gconf-objs	:= gconf.o zconf.tab.o

hostprogs-y := conf

ifeq ($(MAKECMDGOALS),nconfig)
	hostprogs-y += nconf
endif

ifeq ($(MAKECMDGOALS),menuconfig)
	hostprogs-y += mconf
endif

ifeq ($(MAKECMDGOALS),xconfig)
	qconf-target := 1
endif
ifeq ($(MAKECMDGOALS),gconfig)
	gconf-target := 1
endif

ifeq ($(qconf-target),1)
	hostprogs-y += qconf
endif

ifeq ($(gconf-target),1)
	hostprogs-y += gconf
endif

clean-files	:= qconf.moc .tmp_qtcheck .tmp_gtkcheck
clean-files	+= zconf.tab.c zconf.lex.c zconf.hash.c gconf.glade.h
clean-files     += config.pot linux.pot

# Check that we have the required ncurses stuff installed for lxdialog (menuconfig)
$(addprefix $(obj)/, mconf.o $(lxdialog)): $(obj)/.dochecklxdialog
$(obj)/.dochecklxdialog:
	$(Q)$(CONFIG_HOST_SHELL) $(check-lxdialog) -check $(HOSTCC) $(HOST_EXTRACFLAGS) $(HOSTLOADLIBES_mconf)
	$(Q)touch $@

# Add environment specific flags
HOST_EXTRACFLAGS += $(shell $(CONFIG_HOST_SHELL) $(srctree)/$(src)/check.sh $(HOSTCC) $(HOSTCFLAGS))

# generated files seem to need this to find local include files
HOSTCFLAGS_zconf.lex.o	:= -I$(srctree)/$(src)
HOSTCFLAGS_zconf.tab.o	:= -I$(srctree)/$(src)

LEX_PREFIX_zconf	:= zconf
YACC_PREFIX_zconf	:= zconf

HOSTLOADLIBES_qconf	= $(KC_QT_LIBS)
HOSTCXXFLAGS_qconf.o	= $(KC_QT_CFLAGS)

HOSTLOADLIBES_gconf	= `pkg-config --libs gtk+-2.0 gmodule-2.0 libglade-2.0`
HOSTCFLAGS_gconf.o	= `pkg-config --cflags gtk+-2.0 gmodule-2.0 libglade-2.0` \
                          -Wno-missing-prototypes

HOSTLOADLIBES_mconf   = $(shell $(CONFIG_HOST_SHELL) $(check-lxdialog) -ldflags $(HOSTCC))

HOSTLOADLIBES_nconf	= $(shell \
				pkg-config --libs menuw panelw ncursesw 2>/dev/null \
				|| pkg-config --libs menu panel ncurses 2>/dev/null \
				|| echo "-lmenu -lpanel -lncurses"  )
$(obj)/qconf.o: $(obj)/.tmp_qtcheck

ifeq ($(MAKECMDGOALS),xconfig)
$(obj)/.tmp_qtcheck: $(src)/Makefile
-include $(obj)/.tmp_qtcheck

# Qt needs some extra effort...
$(obj)/.tmp_qtcheck:
	@set -e; $(kecho) "  CHECK   qt"; \
	if pkg-config --exists Qt5Core; then \
	    cflags="-std=c++11 -fPIC `pkg-config --cflags Qt5Core Qt5Gui Qt5Widgets`"; \
	    libs=`pkg-config --libs Qt5Core Qt5Gui Qt5Widgets`; \
	    moc=`pkg-config --variable=host_bins Qt5Core`/moc; \
	elif pkg-config --exists QtCore; then \
	    cflags=`pkg-config --cflags QtCore QtGui`; \
	    libs=`pkg-config --libs QtCore QtGui`; \
	    moc=`pkg-config --variable=moc_location QtCore`; \
	else \
	    echo >&2 "*"; \
	    echo >&2 "* Could not find Qt via pkg-config."; \
	    echo >&2 "* Please install either Qt 4.8 or 5.x. and make sure it's in PKG_CONFIG_PATH"; \
	    echo >&2 "*"; \
	    exit 1; \
	fi; \
	echo "KC_QT_CFLAGS=$$cflags" > $@; \
	echo "KC_QT_LIBS=$$libs" >> $@; \
	echo "KC_QT_MOC=$$moc" >> $@
endif

$(obj)/gconf.o: $(obj)/.tmp_gtkcheck

ifeq ($(MAKECMDGOALS),gconfig)
-include $(obj)/.tmp_gtkcheck

# GTK+ needs some extra effort, too...
$(obj)/.tmp_gtkcheck:
	@if `pkg-config --exists gtk+-2.0 gmodule-2.0 libglade-2.0`; then		\
		if `pkg-config --atleast-version=2.0.0 gtk+-2.0`; then			\
			touch $@;								\
		else									\
			echo >&2 "*"; 							\
			echo >&2 "* GTK+ is present but version >= 2.0.0 is required.";	\
			echo >&2 "*";							\
			false;								\
		fi									\
	else										\
		echo >&2 "*"; 								\
		echo >&2 "* Unable to find the GTK+ installation. Please make sure that"; 	\
		echo >&2 "* the GTK+ 2.0 development package is correctly installed..."; 	\
		echo >&2 "* You need gtk+-2.0, glib-2.0 and libglade-2.0."; 		\
		echo >&2 "*"; 								\
		false;									\
	fi
endif

$(obj)/zconf.tab.o: $(obj)/zconf.lex.c $(obj)/zconf.hash.c

$(obj)/qconf.o: $(obj)/qconf.moc

$(obj)/%.moc: $(src)/%.h $(obj)/.tmp_qtcheck
	$(call kconfig_action,MOC,$@,)$(KC_QT_MOC) -i $< -o $@

# Extract gconf menu items for i18n support
$(obj)/gconf.glade.h: $(obj)/gconf.glade
	$(Q)intltool-extract --type=gettext/glade --srcdir=$(srctree) \
	$(obj)/gconf.glade

-include $(obj)/.depend
$(obj)/.depend: $(wildcard *.h *.c)
	$(Q)mkdir -p $(@D)
	$(Q)$(HOSTCC) $(HOST_EXTRACFLAGS) $(HOSTCFLAGS) -MM *.c > $@ 2>/dev/null || :

__hostprogs := $(sort $(hostprogs-y) $(hostprogs-m))
host-csingle := $(addprefix $(obj)/,$(foreach m,$(__hostprogs),$(if $($(m)-objs),,$(m))))
host-cmulti := $(addprefix $(obj)/,$(foreach m,$(__hostprogs),\
           $(if $($(m)-cxxobjs),,$(if $($(m)-objs),$(m)))))
host-cxxmulti := $(addprefix $(obj)/,$(foreach m,$(__hostprogs),\
           $(if $($(m)-cxxobjs),$(m),$(if $($(m)-objs),))))
host-cobjs := $(addprefix $(obj)/,$(sort $(foreach m,$(__hostprogs),$($(m)-objs))))
host-cxxobjs := $(addprefix $(obj)/,$(sort $(foreach m,$(__hostprogs),$($(m)-cxxobjs))))

HOST_EXTRACFLAGS += -I$(obj)

$(host-csingle): %: %.c
	$(Q)mkdir -p $(@D)
	$(call kconfig_action,CC,$@)$(HOSTCC) $(HOST_EXTRACFLAGS) $(HOSTCFLAGS) $(HOSTCFLAGS_$(@F)) $< -o $@

$(host-cmulti): %: $(host-cobjs) $(host-cshlib)
	$(Q)mkdir -p $(@D)
	$(call kconfig_action,CC,$@)$(HOSTCC) $(HOST_EXTRACFLAGS) $(HOSTCFLAGS) $(HOSTCFLAGS_$(@F)) $(addprefix $(obj)/,$($(@F)-objs)) $(HOSTLOADLIBES_$(@F)) -o $@

$(host-cxxmulti): %: $(host-cxxobjs) $(host-cobjs) $(host-cshlib)
	$(Q)mkdir -p $(@D)
	$(call kconfig_action,CXX,$@)$(HOSTCXX) $(HOST_EXTRACFLAGS) $(HOSTCFLAGS) $(HOSTCXXFLAGS_$(@F)) $(addprefix $(obj)/,$($(@F)-objs) $($(@F)-cxxobjs)) $(HOSTLOADLIBES_$(@F)) -o $@

$(obj)/%.o: $(obj)/%.c
	$(Q)mkdir -p $(@D)
	$(call kconfig_action,CC,$@)$(HOSTCC) $(HOST_EXTRACFLAGS) $(HOSTCFLAGS) $(HOSTCFLAGS_$(@F)) -c $< -o $@

$(obj)/%.o: $(obj)/%.cc
	$(Q)mkdir -p $(@D)
	$(call kconfig_action,CC,$@)$(HOSTCC) $(HOST_EXTRACFLAGS) $(HOSTCFLAGS) $(HOSTCXXFLAGS_$(@F)) -c $< -o $@

$(obj)/%:: $(src)/%_shipped
	$(Q)mkdir -p $(@D)
	$(Q)cat $< > $@

clean:
	$(Q)rm -f $(addprefix $(obj)/,$(clean-files))

distclean: clean
	$(Q)rm -f $(addprefix $(obj)/,$(lxdialog) $(conf-objs) $(mconf-objs) \
		$(qconf-cxxobjs) $(qconf-objs) $(gconf-objs) \
		conf nconf mconf qconf gconf .depend .dochecklxdialog)

.PHONY: clean distclean $(PHONY)
