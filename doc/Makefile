ASCIIDOC := asciidoc
A2X := a2x

ASCIIDOC_FLAGS := -a toc -d manpage -a revnumber=$(VERSION)
A2X_FLAGS := -d manpage -a revnumber=$(VERSION)

ASCIIDOC_SOURCES := \
        doc/cenv.9.txt \
        doc/init.9.txt \
        doc/intro.9.txt \
        doc/style.9.txt

ASCIIDOC_MANDOCS := $(patsubst %.9.txt,%.9,$(ASCIIDOC_SOURCES))
ASCIIDOC_HTMLDOCS := $(patsubst %.9.txt,%.9.html,$(ASCIIDOC_SOURCES))

define DOC_HELP
	@printf 'Documentation targets:\n'
	@printf '  docs                     - Build all documentation\n'
	@printf '  mandocs                  - Build man pages\n'
	@printf '  htmldocs                 - Build HTML man pages\n'
	@printf '\n'
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

define htmldocs_install_targets
	$(foreach htmlpage,$(notdir $(ASCIIDOC_HTMLDOCS)),$(htmlpage)_html_install)
endef

%_html_install: doc/%
	install -D -m 644 $< $(DESTDIR)$(PREFIX)/$(DATAROOTDIR)/doc/x15/$*

.PHONY: docs_install
docs_install: $(mandocs_install_targets) $(htmldocs_install_targets)

define docs_clean
	$(Q)rm -f $(ASCIIDOC_MANDOCS) \
	$(ASCIIDOC_HTMLDOCS)
endef

.PHONY: docs_clean
docs_clean:
	$(call docs_clean)

.PHONY: docs_distclean
docs_distclean:
