ASCIIDOC := asciidoc
A2X := a2x

ASCIIDOC_FLAGS := -a toc -d manpage -a revnumber=$(VERSION)
A2X_FLAGS := -d manpage -a revnumber=$(VERSION)

ASCIIDOC_SOURCES := \
        doc/cenv.9.txt \
        doc/init.9.txt \
        doc/intro.9.txt \
        doc/style.9.txt \
        doc/xbuild.9.txt

ASCIIDOC_MANDOCS := $(patsubst %.9.txt,%.9,$(ASCIIDOC_SOURCES))
ASCIIDOC_HTMLDOCS := $(patsubst %.9.txt,%.9.html,$(ASCIIDOC_SOURCES))

define DOC_HELP
	@printf '* mandocs                  - Build man pages\n'
	@printf '* htmldocs                 - Build HTML man pages\n'
endef

define DOC_INSTALL_HELP
	@printf '  install-mandocs          - Install man pages\n'
	@printf '  install-htmldocs         - Install HTML man pages\n'
endef

# Expose intermediate DocBook files for correct parallel builds.
%.9.xml: %.9.txt doc/asciidoc.conf $(ALL_MAKEFILES)
	$(call xbuild_action_mkdir,$@)
	$(Q)$(ASCIIDOC) $(ASCIIDOC_FLAGS) -b docbook -o $@ $<

%.9: %.9.xml doc/asciidoc.conf $(ALL_MAKEFILES)
	$(call xbuild_action,MAN,$@) \
		$(A2X) $(A2X_FLAGS) -f manpage $<

%.9.html: %.9.txt doc/asciidoc.conf $(ALL_MAKEFILES)
	$(call xbuild_action,HTML,$@) \
		$(ASCIIDOC) $(ASCIIDOC_FLAGS) -b html5 -o $@ $<

.PHONY: mandocs
mandocs: $(ASCIIDOC_MANDOCS)

.PHONY: htmldocs
htmldocs: $(ASCIIDOC_HTMLDOCS)

.PHONY: docs
docs: mandocs htmldocs

define mandocs_install_targets
	$(foreach manpage,$(notdir $(ASCIIDOC_MANDOCS)),$(manpage)_man_install)
endef

%_man_install: doc/%
	install -D -m 644 $< $(DESTDIR)$(PREFIX)/$(DATAROOTDIR)/man/man9/$*

.PHONY: install-mandocs
install-mandocs: $(mandocs_install_targets)

.PHONY: install-htmldocs
install-htmldocs: $(htmldocs_install_targets)

define htmldocs_install_targets
	$(foreach htmlpage,$(notdir $(ASCIIDOC_HTMLDOCS)),$(htmlpage)_html_install)
endef

%_html_install: doc/%
	install -D -m 644 $< $(DESTDIR)$(PREFIX)/$(DATAROOTDIR)/doc/x15/$*

.PHONY: install-docs
install-docs: install-mandocs install-htmldocs

define clean_docs
	$(Q)rm -f $(ASCIIDOC_MANDOCS) \
	$(ASCIIDOC_HTMLDOCS)
endef

.PHONY: clean-docs
clean-docs:
	$(call clean_docs)

.PHONY: distclean-docs
distclean-docs: clean-docs
