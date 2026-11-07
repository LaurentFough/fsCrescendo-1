#= ---------------------------------------------------------------------------
#= Makefile  -- version 1.6.0  (2026-11-07)
#= Build / lint / test / debug / clean helpers for fsCrescendo.
#= Usage  : make help
#= Needs  : macOS 13+. `make build` uses full Xcode if usable, else the Command Line Tools
#=          (compile check only: no .app, no signing). Optional: swiftlint.
#=          Info targets (help, doctor, version, selftest) also run on Linux.
#= Compat : written for GNU Make 3.81 (the version Apple ships) and newer.
#= Notes  : products go to ./build (git-ignored). Builds are UNSIGNED by default:
#=          fine as a compile check, but the Endpoint Security extension will not
#=          load unless you use `make build-signed TEAM=<id>`.
#= ---------------------------------------------------------------------------

MAKEFILE_VERSION := 1.6.0
SHELL            := /bin/bash
.DEFAULT_GOAL    := help

#= ---- configuration (override on the command line: make build CONFIG=Release) ----
PROJECT     ?= CrescendoFramework.xcodeproj
PYTHON      ?= python3
APP_TARGET  ?= Crescendo
EXT_TARGET  ?= CrescendoExtension
LIB_TARGET  ?= libCrescendo
CONFIG      ?= Debug
BUILD_DIR   ?= build
INSTALL_DIR ?= /Applications
TEAM        ?=
TEST_SCHEME ?=
NAMES       ?= Crescendo
LAST        ?= 5m
ES_EVENTS   ?= exec fork exit create rename unlink
LOGFILE     ?=
BUILD_MODE  ?= auto
SIGN        ?= local
APP_ENT     ?= Crescendo/CrescendoApp.entitlements
EXT_ENT     ?= CrescendoExtension/CrescendoExtension.entitlements
FORCE       ?= 0
MIN_MACOS   ?= 13.0
SWIFTC      ?= xcrun swiftc
CONFIRM     ?= 0
V           ?= 0

#= user-supplied values reach recipes through the environment ("$$VAR"), never pasted into shell text,
#= so quotes or spaces in them are data, not shell syntax.
export NAMES LAST ES_EVENTS TEAM BUILD_MODE SIGN FORCE CONFIRM

SYMROOT  := $(CURDIR)/$(BUILD_DIR)/products
OBJROOT  := $(CURDIR)/$(BUILD_DIR)/obj
APP_PATH := $(SYMROOT)/$(CONFIG)/$(APP_TARGET).app

ifeq ($(V),1)
QUIET :=
else
QUIET := -quiet
endif

XCODE_DETECT   ?= scripts/xcode-detect.sh
#= XCODE_DIR runs the detector once per make run, only when an Xcode target needs it (lazy + memoised).
#= It finds an installed Xcode even when xcode-select points at the Command Line Tools, so no sudo is needed.
#= (Assumes the Xcode path has no spaces.)
XCODE_DIR       = $(eval XCODE_DIR := $(shell sh $(XCODE_DETECT) --dir 2>/dev/null))$(XCODE_DIR)
XCB             = $(if $(XCODE_DIR),DEVELOPER_DIR="$(XCODE_DIR)" )xcodebuild -project $(PROJECT) -configuration $(CONFIG) SYMROOT=$(SYMROOT) OBJROOT=$(OBJROOT) ARCHS=$(ARCH) ONLY_ACTIVE_ARCH=NO
UNSIGNED_FLAGS := CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY=
SIGNED_FLAGS   := CODE_SIGN_STYLE=Automatic $(if $(TEAM),DEVELOPMENT_TEAM=$(TEAM)) -allowProvisioningUpdates

#= SIGN picks how the app is signed:
#=   local = "Sign to Run Locally" (default): xcodebuild builds UNSIGNED (Xcode refuses restricted entitlements
#=           without a provisioning profile), then scripts/local-sign.sh ad-hoc signs with the entitlements
#=   none  = unsigned, no signing step      team = your Apple Team ID (needs TEAM=<id>)
SIGN_FLAGS_local := $(UNSIGNED_FLAGS)
SIGN_FLAGS_none  := $(UNSIGNED_FLAGS)
SIGN_FLAGS_team  := $(SIGNED_FLAGS)
SIGN_FLAGS        = $(SIGN_FLAGS_$(SIGN))

#= Command Line Tools mode: swiftc/clang against the macOS SDK. SDK_PATH is lazy (xcrun only runs when used).
ARCH      := $(shell uname -m)
SDK_PATH   = $(shell xcrun --sdk macosx --show-sdk-path 2>/dev/null)
CLT_OUT   := $(CURDIR)/$(BUILD_DIR)/clt
LIB_SRCS  := $(wildcard libCrescendo/*.swift)
EXT_SRCS  := CrescendoExtension/main.swift CrescendoExtension/IPCConnection.swift
APP_SRCS  := $(wildcard Crescendo/*.swift) CrescendoExtension/IPCConnection.swift
SWIFT_COMMON = -sdk "$(SDK_PATH)" -target $(ARCH)-apple-macosx$(MIN_MACOS) -swift-version 5
ES_MODULE_DIR := libCrescendo/EndpointModule

#= say: timestamped log line to stdout (and appended to $(LOGFILE) if set). Avoid commas in the text.
define say
printf '%s make[$(MAKEFILE_VERSION)]: %s\n' "$$(date '+%Y-%m-%dT%H:%M:%S')" "$(1)" $(if $(LOGFILE),| tee -a "$(LOGFILE)")
endef

.PHONY: help version doctor list selftest \
        build build-xcode build-clt build-lib build-ext build-signed lint check test \
        install run logs logs-sandbox logs-replay crashes \
        sysext-list sysext-dev-on sysext-dev-off entitlements verify-sign eslogger \
        clean distclean \
        check-signing install-hooks local-sign probe-sandbox-net probe-sandbox-net-json fsx fsx-test \
        require-macos require-xcode require-clt require-team require-sign require-safe-builddir

#= ---------------------------------------------------------------------------
#= Info
#= ---------------------------------------------------------------------------
help: #= Show this help
	@echo "fsCrescendo Makefile $(MAKEFILE_VERSION)"
	@echo
	@echo "Targets:"
	@awk 'BEGIN{FS=":.*#= "} /^[a-zA-Z0-9_.-]+:.*#= /{printf "  %-16s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo
	@echo "Variables (current): CONFIG=$(CONFIG) BUILD_DIR=$(BUILD_DIR) TEAM=$(TEAM) NAMES='$(NAMES)' LAST=$(LAST) V=$(V)"
	@echo "Examples:"
	@echo "  make doctor                       # what is installed / enabled"
	@echo "  make build                        # Xcode if usable, else Command Line Tools compile check"
	@echo "  make build DEVELOPER_DIR=/path/Xcode.app/Contents/Developer   # pick an Xcode without sudo"
	@echo "  make build                        # signs locally (ad-hoc); SIGN=none or SIGN=team TEAM=<id> to change"
	@echo "  make check-signing                # project must only use Sign to Run Locally"
	@echo "  make build-signed TEAM=ABCDE12345 # signed with YOUR team (never commit that setting)"
	@echo "  make logs-sandbox NAMES='the-binary ioreg'"

version: #= Print Makefile and git versions
	@echo "Makefile $(MAKEFILE_VERSION)"
	@git describe --always --dirty --tags 2>/dev/null || echo "git: not a repository"

doctor: #= Environment report: OS, Xcode, tools, SIP/AMFI, repo state
	@echo "== host";  uname -sm; if command -v sw_vers >/dev/null; then sw_vers; else echo "  (not macOS: build targets unavailable)"; fi
	@echo "== tools"; for t in xcodebuild swiftc xcrun swiftlint git codesign systemextensionsctl eslogger log; do printf '  %-22s' $$t; command -v $$t || echo "-"; done
	@echo "== xcode"; sh $(XCODE_DETECT) --human; if sh $(XCODE_DETECT) --dir >/dev/null 2>&1; then echo "  make build -> full Xcode"; else echo "  make build -> Command Line Tools (compile check only)"; fi
	@echo "== sip / amfi (only a dev VM needs these relaxed; see README)"; if command -v csrutil >/dev/null; then csrutil status; else echo "  csrutil n/a"; fi; if command -v nvram >/dev/null; then nvram boot-args 2>/dev/null || echo "  boot-args: (none)"; fi
	@echo "== repo"; git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "  not a git checkout"; if [ -d "$(PROJECT)" ]; then echo "  project: $(PROJECT) ok"; else echo "  project: $(PROJECT) MISSING (run from the repo root)"; fi

list: require-xcode #= List the Xcode targets, configurations and schemes
	@$(XCB) -list

selftest: #= Sanity-check this Makefile with dry runs (works on any OS)
	@$(MAKE) --no-print-directory help >/dev/null
	@for t in build build-xcode build-clt fsx fsx-test probe-sandbox-net probe-sandbox-net-json local-sign check-signing install-hooks build-lib build-ext build-signed install run logs logs-sandbox logs-replay crashes sysext-list sysext-dev-on sysext-dev-off entitlements verify-sign clean; do \
	  $(MAKE) --no-print-directory -n $$t TEAM=ABCDE12345 >/dev/null 2>&1 || { echo "selftest FAIL: $$t" >&2; exit 1; }; \
	done
	@sh $(XCODE_DETECT) --env >/dev/null || { echo "selftest FAIL: $(XCODE_DETECT)" >&2; exit 1; }
	@$(call say,selftest ok)

#= ---------------------------------------------------------------------------
#= Guards (prerequisites, not meant to be run directly)
#= ---------------------------------------------------------------------------
require-macos:
	@[ "$$(uname -s)" = Darwin ] || { echo "ERROR: this target needs macOS" >&2; exit 2; }

require-xcode: require-macos
	@sh $(XCODE_DETECT) --dir >/dev/null 2>&1 || { echo "ERROR: no usable Xcode for xcodebuild" >&2; sh $(XCODE_DETECT) --why >&2; exit 2; }
	@[ -d "$(PROJECT)" ] || { echo "ERROR: $(PROJECT) not found (run make from the repo root)" >&2; exit 66; }
	@case "$(CURDIR)" in *" "*) echo "ERROR: repo path contains a space; unsupported by this Makefile: $(CURDIR)" >&2; exit 65;; esac

require-clt: require-macos
	@command -v xcrun >/dev/null || { echo "ERROR: xcrun not found - install the Command Line Tools: xcode-select --install" >&2; exit 2; }
	@xcrun --sdk macosx --show-sdk-path >/dev/null 2>&1 || { echo "ERROR: no macOS SDK found - run: xcode-select --install" >&2; exit 2; }
	@xcrun --find swiftc >/dev/null 2>&1 || { echo "ERROR: swiftc not found - run: xcode-select --install" >&2; exit 2; }
	@[ -d "$(ES_MODULE_DIR)" ] || { echo "ERROR: $(ES_MODULE_DIR) not found (run make from the repo root)" >&2; exit 66; }
	@case "$(CURDIR)" in *" "*) echo "ERROR: repo path contains a space; unsupported by this Makefile: $(CURDIR)" >&2; exit 65;; esac

require-sign:
	@case "$$SIGN" in local|none) ;; team) printf '%s' "$$TEAM" | grep -Eq '^[A-Z0-9]{10}$$' || { echo "ERROR: SIGN=team needs TEAM=<10-character Team ID>" >&2; exit 64; };; *) echo "ERROR: SIGN must be local, none or team (got: $$SIGN)" >&2; exit 64;; esac

require-team:
	@printf '%s' "$$TEAM" | grep -Eq '^[A-Z0-9]{10}$$' || { echo "ERROR: set TEAM=<10-character Apple Team ID>" >&2; exit 64; }

require-safe-builddir:
	@case "$(BUILD_DIR)" in ""|/*|.|..|*..*) echo "ERROR: unsafe BUILD_DIR='$(BUILD_DIR)'" >&2; exit 65;; esac

#= ---------------------------------------------------------------------------
#= Build and test
#= ---------------------------------------------------------------------------
build: require-macos #= Build: full Xcode if usable, else Command Line Tools compile check (BUILD_MODE=auto|xcode|clt)
	@mode="$$BUILD_MODE"; \
	if [ "$$mode" = auto ]; then \
	  if sh $(XCODE_DETECT) --dir >/dev/null 2>&1; then mode=xcode; else mode=clt; fi; \
	fi; \
	case "$$mode" in xcode|clt) ;; *) echo "ERROR: BUILD_MODE must be auto, xcode or clt (got: $$mode)" >&2; exit 64;; esac; \
	$(call say,build mode: $$mode); \
	if [ "$$mode" = clt ]; then sh $(XCODE_DETECT) --why >&2 || true; fi; \
	exec $(MAKE) --no-print-directory build-$$mode

build-xcode: require-xcode require-sign #= Full Xcode build; SIGN=local (default) builds unsigned then ad-hoc signs with entitlements
	@$(call say,building $(APP_TARGET) [$(CONFIG)] sign=$(SIGN) with xcodebuild)
	@$(XCB) -target $(APP_TARGET) $(QUIET) $(SIGN_FLAGS) build
	@if [ "$$SIGN" = local ]; then $(MAKE) --no-print-directory local-sign; fi
	@$(call say,build ok: $(APP_PATH))

build-clt: require-clt #= Command Line Tools compile check ONLY: no .app, no storyboards, no signing
	@$(call say,Command Line Tools mode: compile check only - no .app is produced)
	@mkdir -p "$(CLT_OUT)"
	@$(call say,[1/4] libCrescendo: compile the Swift module)
	@$(SWIFTC) $(SWIFT_COMMON) -I $(ES_MODULE_DIR) -parse-as-library -module-name libCrescendo -emit-module -emit-module-path "$(CLT_OUT)/libCrescendo.swiftmodule" $(LIB_SRCS)
	@$(call say,[2/4] CrescendoExtension: type-check)
	@$(SWIFTC) $(SWIFT_COMMON) -I "$(CLT_OUT)" -I $(ES_MODULE_DIR) -module-name CrescendoExtension -typecheck $(EXT_SRCS)
	@$(call say,[3/4] Crescendo app Swift sources: type-check)
	@$(SWIFTC) $(SWIFT_COMMON) -I "$(CLT_OUT)" -I $(ES_MODULE_DIR) -import-objc-header Crescendo/Crescendo-Bridging-Header.h -module-name Crescendo -typecheck $(APP_SRCS)
	@$(call say,[4/4] PFMoveApplication.m: syntax check)
	@xcrun clang -fsyntax-only -fno-objc-arc -isysroot "$(SDK_PATH)" -target $(ARCH)-apple-macosx$(MIN_MACOS) Crescendo/ThirdParty/PFMoveApplication.m
	@$(call say,Command Line Tools compile check passed - for a runnable app use full Xcode: make build-signed TEAM=<id>)

build-lib: require-xcode require-sign #= Compile only the libCrescendo framework (SIGN as above)
	@$(call say,building $(LIB_TARGET) [$(CONFIG)] sign=$(SIGN))
	@$(XCB) -target $(LIB_TARGET) $(QUIET) $(SIGN_FLAGS) build

build-ext: require-xcode require-sign #= Compile only the system extension (SIGN as above)
	@$(call say,building $(EXT_TARGET) [$(CONFIG)] sign=$(SIGN))
	@$(XCB) -target $(EXT_TARGET) $(QUIET) $(SIGN_FLAGS) build

build-signed: require-xcode require-team #= Build signed with YOUR Team ID (TEAM=<id>); same as SIGN=team
	@$(call say,building $(APP_TARGET) [$(CONFIG)] signed with team $(TEAM))
	@$(XCB) -target $(APP_TARGET) $(QUIET) $(SIGNED_FLAGS) build
	@$(call say,build ok: $(APP_PATH))

lint: #= Run swiftlint if installed (skips with a note otherwise)
	@if command -v swiftlint >/dev/null; then swiftlint lint --quiet; else echo "swiftlint not installed - skipping (brew install swiftlint)"; fi

check: #= Signing check + whitespace check + lint + build (run before pushing)
	@$(MAKE) --no-print-directory check-signing
	@git diff --check
	@$(MAKE) --no-print-directory lint
	@$(MAKE) --no-print-directory build

test: require-xcode require-sign #= Run Xcode tests (set TEST_SCHEME=<scheme>; the repo has no tests yet)
	@if [ -n "$(TEST_SCHEME)" ]; then \
	  $(call say,testing scheme $(TEST_SCHEME)); \
	  $(XCB) -scheme "$(TEST_SCHEME)" $(QUIET) $(SIGN_FLAGS) test; \
	else \
	  echo "No test scheme set: the repo has no unit tests yet (plan phase P1)."; \
	  echo "Add a test target, then run: make test TEST_SCHEME=<scheme>"; \
	fi

local-sign: require-macos #= Ad-hoc sign the built app + extension with their entitlements (Sign to Run Locally)
	@sh scripts/local-sign.sh "$(APP_PATH)" "$(APP_ENT)" "$(EXT_ENT)"

check-signing: #= Fail if the Xcode project has a Team ID, certificate or profile (local ad-hoc signing only)
	@sh scripts/check-signing.sh

install-hooks: #= Install a git pre-commit hook that runs check-signing (FORCE=1 to overwrite)
	@hook=.git/hooks/pre-commit; \
	[ -d .git/hooks ] || { echo "ERROR: not a git checkout (.git/hooks missing)" >&2; exit 66; }; \
	if [ -e "$$hook" ] && [ "$$FORCE" != 1 ]; then echo "ERROR: $$hook exists (use FORCE=1 to overwrite)" >&2; exit 65; fi; \
	printf '%s\n' '#!/bin/sh' '#= pre-commit hook installed by make install-hooks (fsCrescendo): blocks commits with non-local signing' 'root=$$(git rev-parse --show-toplevel) || exit 1' 'exec sh "$$root/scripts/check-signing.sh" --quiet' > "$$hook"; \
	chmod +x "$$hook"; \
	$(call say,installed $$hook)

#= ---------------------------------------------------------------------------
#= Install, run, debug
#= ---------------------------------------------------------------------------
install: require-macos #= Copy the built app to INSTALL_DIR (system extensions must run from /Applications)
	@[ -d "$(APP_PATH)" ] || { echo "ERROR: $(APP_PATH) not found - run make build-signed first" >&2; exit 66; }
	@$(call say,installing to $(INSTALL_DIR)/$(APP_TARGET).app)
	@ditto "$(APP_PATH)" "$(INSTALL_DIR)/$(APP_TARGET).app"

run: require-macos #= Open the installed app
	@[ -d "$(INSTALL_DIR)/$(APP_TARGET).app" ] || { echo "ERROR: not installed - run make install" >&2; exit 66; }
	@open "$(INSTALL_DIR)/$(APP_TARGET).app"

logs: require-macos #= Stream app and extension logs (NSLog) that mention "crescendo"
	@log stream --style compact --predicate 'eventMessage CONTAINS[c] "crescendo" OR process CONTAINS[c] "crescendo"'

logs-sandbox: require-macos #= Stream Seatbelt (Sandbox) denials mentioning NAMES="a b ..."
	@pred=''; \
	for n in $$NAMES; do \
	  case "$$n" in *\"*|*\\*|*\'*) echo "ERROR: bad name: $$n" >&2; exit 65;; esac; \
	  pred="$${pred:+$$pred OR }eventMessage CONTAINS \"$$n\""; \
	done; \
	[ -n "$$pred" ] || { echo "ERROR: NAMES is empty" >&2; exit 64; }; \
	$(call say,watching Sandbox denials for: $$NAMES); \
	exec log stream --style compact --predicate "sender == \"Sandbox\" AND eventMessage CONTAINS \"deny\" AND ($$pred)"

fsx: #= Show the fsx engine help (sandbox-denial triage and managed sandbox sessions, tools/fsx)
	@cd tools/fsx && $(PYTHON) -m fsx --help

fsx-test: #= Run the fsx unit and end-to-end tests (any OS; needs only python3 3.9+)
	@cd tools/fsx && $(PYTHON) -W ignore::ResourceWarning -m unittest discover -s tests -t .

probe-sandbox-net: require-macos #= Test how sandbox-exec handles outbound-network rules here (add --external via the script)
	@sh scripts/probe-sandbox-net.sh

probe-sandbox-net-json: require-macos #= Same probe, machine-readable JSON (fsx.sandbox-net-probe/1)
	@sh scripts/probe-sandbox-net.sh --json

logs-replay: require-macos #= Show Sandbox denials from the last LAST (default 5m) for NAMES
	@printf '%s' "$$LAST" | grep -Eq '^[0-9]+[smhd]$$' || { echo "ERROR: LAST must look like 90s 5m 2h 1d" >&2; exit 64; }
	@pred=''; \
	for n in $$NAMES; do \
	  case "$$n" in *\"*|*\\*|*\'*) echo "ERROR: bad name: $$n" >&2; exit 65;; esac; \
	  pred="$${pred:+$$pred OR }eventMessage CONTAINS \"$$n\""; \
	done; \
	[ -n "$$pred" ] || { echo "ERROR: NAMES is empty" >&2; exit 64; }; \
	log show --last "$$LAST" --style compact --predicate "sender == \"Sandbox\" AND eventMessage CONTAINS \"deny\" AND ($$pred)"

crashes: #= List Crescendo crash reports, newest first
	@ls -t "$$HOME/Library/Logs/DiagnosticReports" /Library/Logs/DiagnosticReports 2>/dev/null | grep -i crescendo | head -20 || echo "no Crescendo crash reports found"

sysext-list: require-macos #= List installed system extensions and their state
	@systemextensionsctl list

sysext-dev-on: require-macos #= Enable system-extension developer mode (reload on every submit; dev VM)
	@$(call say,enabling system extension developer mode)
	@systemextensionsctl developer on

sysext-dev-off: require-macos #= Disable system-extension developer mode
	@systemextensionsctl developer off

entitlements: require-macos #= Show the entitlements of the built app and its embedded extension
	@[ -d "$(APP_PATH)" ] || { echo "ERROR: $(APP_PATH) not found - build first" >&2; exit 66; }
	@show() { out=$$(codesign -d --entitlements - --xml "$$1" 2>/dev/null); [ -n "$$out" ] || out=$$(codesign -d --entitlements :- "$$1" 2>/dev/null); if [ -z "$$out" ]; then echo "  (no entitlements)"; elif command -v plutil >/dev/null 2>&1; then printf '%s\n' "$$out" | plutil -p - 2>/dev/null || printf '%s\n' "$$out"; else printf '%s\n' "$$out"; fi; }; \
	echo "== app"; show "$(APP_PATH)"; \
	for e in "$(APP_PATH)"/Contents/Library/SystemExtensions/*.systemextension; do [ -e "$$e" ] || continue; echo "== $$e"; show "$$e"; done

verify-sign: require-macos #= Verify the code signature of the built app (deep, strict)
	@[ -d "$(APP_PATH)" ] || { echo "ERROR: $(APP_PATH) not found - build first" >&2; exit 66; }
	@codesign --verify --deep --strict --verbose=2 "$(APP_PATH)"

eslogger: require-macos #= Prototype event source (macOS 13+): sudo eslogger ES_EVENTS
	@printf '%s' "$$ES_EVENTS" | grep -Eq '^[a-z_ ]+$$' || { echo "ERROR: ES_EVENTS must be lowercase event names" >&2; exit 64; }
	@major=$$(sw_vers -productVersion | cut -d. -f1); [ "$$major" -ge 13 ] || { echo "ERROR: eslogger needs macOS 13 or newer" >&2; exit 2; }
	@$(call say,eslogger $$ES_EVENTS - needs root and Full Disk Access for the terminal app)
	@sudo eslogger $$ES_EVENTS

#= ---------------------------------------------------------------------------
#= Clean-up
#= ---------------------------------------------------------------------------
clean: require-safe-builddir #= Remove build products (./build)
	@$(call say,removing $(BUILD_DIR))
	@rm -rf "$(BUILD_DIR)"

distclean: clean #= Preview ignored files git would delete; CONFIRM=1 actually deletes them
	@if [ "$$CONFIRM" = 1 ]; then git clean -fdX; else echo "Dry run (add CONFIRM=1 to delete):"; git clean -ndX; fi
