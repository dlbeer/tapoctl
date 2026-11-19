# Builds a single self-contained executable (a Python zipapp) that needs
# only the system python3 to run.

PYTHON ?= python3
PREFIX ?= /usr/local
BUILD := build

VERSION := $(shell git describe --always --dirty --tags 2>/dev/null || echo unknown) \
	$(shell date -u +%Y-%m-%dT%H:%M:%SZ) \
	$(shell id -un)@$(shell hostname)

SOURCES := $(wildcard src/tapoctl/*.py)

all: tapoctl

tapoctl: $(SOURCES) FORCE
	rm -rf $(BUILD)
	mkdir -p $(BUILD)/tapoctl
	cp src/tapoctl/*.py $(BUILD)/tapoctl/
	rm -f $(BUILD)/tapoctl/_version.py
	echo 'VERSION = "$(strip $(VERSION))"' > $(BUILD)/tapoctl/_version.py
	$(PYTHON) -m zipapp $(BUILD) -c -p '/usr/bin/env python3' \
		-m 'tapoctl.cli:main' -o $@

install: tapoctl
	install -m 0755 tapoctl $(DESTDIR)$(PREFIX)/bin/tapoctl

test:
	$(PYTHON) -m unittest discover -s tests -t .

clean:
	rm -rf $(BUILD) tapoctl

.PHONY: all install test clean FORCE
