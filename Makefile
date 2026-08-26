# sod — build & packaging. Signing/notarization gracefully no-op when env unset.
# Set DEVELOPER_ID_APP / DEVELOPER_ID_INSTALLER / NOTARY_PROFILE to sign + notarize.
SHELL := /bin/bash
VERSION := $(shell git describe --tags --always 2>/dev/null || echo 0.0.0)
BIN := dist/sd

.DEFAULT_GOAL := build
.PHONY: version build universal test lint man pkg sign notarize staple install uninstall clean release

version: ## write Sources/sod/Version.swift from git
	@bash scripts/gen-version.sh

build: version ## native release build
	swift build -c release

universal: ## staged universal (arm64+x86_64) dist/sd
	bash scripts/build-universal.sh

test: ## XCTest-free unit tests + mock end-to-end self-test
	SE_SSH_MOCK=1 swift run sod-tests
	SE_SSH_MOCK=1 bash scripts/selftest.sh /tmp/sod-make-selftest

lint: ## swift-format strict lint
	swift format lint --strict --recursive Sources Tests

man: ## lint the man page
	@mandoc -Tlint man/sd.1 && echo "man: sd.1 OK"

sign: universal ## codesign dist/sd IFF $$DEVELOPER_ID_APP set
	bash scripts/sign.sh

pkg: universal sign man ## build (and sign-if-able) the .pkg
	bash scripts/make-pkg.sh

notarize: ## submit+staple IFF $$NOTARY_PROFILE set
	bash scripts/notarize.sh

staple: ## staple an already-notarized pkg
	@PKG=$$(ls -t dist/sod-*.pkg | head -1); xcrun stapler staple "$$PKG" && xcrun stapler validate "$$PKG"

install: universal ## install to /usr/local (sudo)
	sudo install -d /usr/local/bin /usr/local/share/man/man1
	sudo install -m 0755 $(BIN) /usr/local/bin/sd
	sudo install -m 0644 man/sd.1 /usr/local/share/man/man1/sd.1
	sudo bash scripts/gen-completions.sh $(BIN)

uninstall: ## remove local install + optional LaunchAgent
	sudo rm -f /usr/local/bin/sd /usr/local/share/man/man1/sd.1 \
	  /usr/local/share/zsh/site-functions/_sd \
	  /usr/local/etc/bash_completion.d/sd \
	  /usr/local/share/fish/vendor_completions.d/sd.fish
	-launchctl bootout gui/$$(id -u)/consulting.botanica.sod.agent 2>/dev/null
	rm -f ~/Library/LaunchAgents/consulting.botanica.sod.agent.plist

clean: ## remove build + generated artifacts
	swift package clean
	rm -rf dist Sources/sod/Version.swift packaging/resources/LICENSE.txt

release: clean test universal sign pkg notarize ## full pipeline (signing/notary self-skip if env unset)
	@echo "release $(VERSION): artifacts in dist/ (signed+notarized only if DEVELOPER_ID_* / NOTARY_PROFILE were set)"
	@ls -la dist/*.pkg dist/sd 2>/dev/null || true
