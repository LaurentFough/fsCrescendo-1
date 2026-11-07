#= ---------------------------------------------------------------------------
#= Makefile  -- version 1.0.1  (2026-11-07)
#= Build / lint / test / debug / clean helpers for fsCrescendo.
#= Usage  : make help
#= Needs  : macOS 13+ and Xcode (xcodebuild) for build targets. Optional: swiftlint.
#=          Info targets (help, doctor, version, selftest) also run on Linux.
#= Compat : written for GNU Make 3.81 (the version Apple ships) and newer.
#= Notes  : products go to ./build (git-ignored). Builds are UNSIGNED by default:
#=          fine as a compile check, but the Endpoint Security extension will not
#=          load unless you use `make build-signed TEAM=<id>`.
#= ---------------------------------------------------------------------------

MAKEFILE_VERSION := 1.0.1
SHELL            := /bin/bash
.DEFAULT_GOAL    := help

#= ---- configuration (override on the command line: make build CONFIG=Release) ----
PROJECT     ?= CrescendoFramework.xcodeproj
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
CONFIRM     ?= 0
V           ?= 0

#= user-supplied values reach recipes through the environment ("$$VAR"), never pasted into shell text,
#= so quotes or spaces in them are data, not shell syntax.
export NAMES LAST ES_EVENTS TEAM

SYMROOT  := $(CURDIR)/$(BUILD_DIR)/products
OBJROOT  := $(CURDIR)/$(BUILD_DIR)/obj
APP_PATH := $(SYMROOT)/$(CONFIG)/$(APP_TARGET).app

ifeq ($(V),1)
QUIET :=
else
QUIET := -quiet
endif

XCB            := xcodebuild -project $(PROJECT) -configuration $(CONFIG) SYMROOT=$(SYMROOT) OBJROOT=$(OBJROOT)
UNSIGNED_FLAGS := CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY=
SIGNED_FLAGS   := CODE_SIGN_STYLE=Automatic $(if $(TEAM),DEVELOPMENT_TEAM=$(TEAM)) -allowProvisioningUpdates

#= say: timestamped log line to stdout (and appended to $(LOGFILE) if set). Avoid commas in the text.
define say
printf '%s make[$(MAKEFILE_VERSION)]: %s\n' "$$(date '+%Y-%m-%dT%H:%M:%S')" "$(1)" $(if $(LOGFILE),| tee -a "$(LOGFILE)")
endef

.PHONY: help version doctor list selftest \
        build build-lib build-ext build-signed lint check test \
        install run logs logs-sandbox logs-replay crashes \
        sysext-list sysext-dev-on sysext-dev-off entitlements verify-sign eslogger \
        clean distclean \
        require-macos require-xcode require-team require-safe-builddir

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
	@echo "  make build                        # unsigned compile check"
	@echo "  make build-signed TEAM=ABCDE12345 # signed build (needs your ES entitlement)"
	@echo "  make logs-sandbox NAMES='the-binary ioreg'"

version: #= Print Makefile and git versions
	@echo "Makefile $(MAKEFILE_VERSION)"
	@git describe --always --dirty --tags 2>/dev/null || echo "git: not a repository"

doctor: #= Environment report: OS, Xcode, tools, SIP/AMFI, repo state
	@echo "== host";  uname -sm; if command -v sw_vers >/dev/null; then sw_vers; else echo "  (not macOS: build targets unavailable)"; fi
	@echo "== tools"; for t in xcodebuild swiftlint git codesign systemextensionsctl eslogger log; do printf '  %-22s' $$t; command -v $$t || echo "-"; done
	@echo "== xcode"; if command -v xcodebuild >/dev/null; then xcodebuild -version; else echo "  xcodebuild not available"; fi
	@echo "== sip / amfi (only a dev VM needs these relaxed; see README)"; if command -v csrutil >/dev/null; then csrutil status; else echo "  csrutil n/a"; fi; if command -v nvram >/dev/null; then nvram boot-args 2>/dev/null || echo "  boot-args: (none)"; fi
	@echo "== repo"; git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "  not a git checkout"; if [ -d "$(PROJECT)" ]; then echo "  project: $(PROJECT) ok"; else echo "  project: $(PROJECT) MISSING (run from the repo root)"; fi

list: require-xcode #= List the Xcode targets, configurations and schemes
	@$(XCB) -list

selftest: #= Sanity-check this Makefile with dry runs (works on any OS)
	@$(MAKE) --no-print-directory help >/dev/null
	@for t in build build-lib build-ext build-signed install run logs logs-sandbox logs-replay crashes sysext-list sysext-dev-on sysext-dev-off entitlements verify-sign clean; do \
	  $(MAKE) --no-print-directory -n $$t TEAM=ABCDE12345 >/dev/null 2>&1 || { echo "selftest FAIL: $$t" >&2; exit 1; }; \
	done
	@$(call say,selftest ok)

#= ---------------------------------------------------------------------------
#= Guards (prerequisites, not meant to be run directly)
#= ---------------------------------------------------------------------------
require-macos:
	@[ "$$(uname -s)" = Darwin ] || { echo "ERROR: this target needs macOS" >&2; exit 2; }

require-xcode: require-macos
	@command -v xcodebuild >/dev/null || { echo "ERROR: xcodebuild not found (install Xcode or run xcode-select --install)" >&2; exit 2; }
	@[ -d "$(PROJECT)" ] || { echo "ERROR: $(PROJECT) not found (run make from the repo root)" >&2; exit 66; }
	@case "$(CURDIR)" in *" "*) echo "ERROR: repo path contains a space; unsupported by this Makefile: $(CURDIR)" >&2; exit 65;; esac

require-team:
	@printf '%s' "$$TEAM" | grep -Eq '^[A-Z0-9]{10}$$' || { echo "ERROR: set TEAM=<10-character Apple Team ID>" >&2; exit 64; }

require-safe-builddir:
	@case "$(BUILD_DIR)" in ""|/*|.|..|*..*) echo "ERROR: unsafe BUILD_DIR='$(BUILD_DIR)'" >&2; exit 65;; esac

#= ---------------------------------------------------------------------------
#= Build and test
#= ---------------------------------------------------------------------------
build: require-xcode #= Compile app + extension + framework UNSIGNED (compile check only)
	@$(call say,building $(APP_TARGET) [$(CONFIG)] unsigned)
	@$(XCB) -target $(APP_TARGET) $(QUIET) $(UNSIGNED_FLAGS) build
	@$(call say,build ok: $(APP_PATH))

build-lib: require-xcode #= Compile only the libCrescendo framework (unsigned)
	@$(call say,building $(LIB_TARGET) [$(CONFIG)] unsigned)
	@$(XCB) -target $(LIB_TARGET) $(QUIET) $(UNSIGNED_FLAGS) build

build-ext: require-xcode #= Compile only the system extension (unsigned)
	@$(call say,building $(EXT_TARGET) [$(CONFIG)] unsigned)
	@$(XCB) -target $(EXT_TARGET) $(QUIET) $(UNSIGNED_FLAGS) build

build-signed: require-xcode require-team #= Signed build (TEAM=<id>); needed for the extension to load
	@$(call say,building $(APP_TARGET) [$(CONFIG)] signed with team $(TEAM))
	@$(XCB) -target $(APP_TARGET) $(QUIET) $(SIGNED_FLAGS) build
	@$(call say,build ok: $(APP_PATH))

lint: #= Run swiftlint if installed (skips with a note otherwise)
	@if command -v swiftlint >/dev/null; then swiftlint lint --quiet; else echo "swiftlint not installed - skipping (brew install swiftlint)"; fi

check: #= Whitespace check + lint + build (run before pushing)
	@git diff --check
	@$(MAKE) --no-print-directory lint
	@$(MAKE) --no-print-directory build

test: require-xcode #= Run Xcode tests (set TEST_SCHEME=<scheme>; the repo has no tests yet)
	@if [ -n "$(TEST_SCHEME)" ]; then \
	  $(call say,testing scheme $(TEST_SCHEME)); \
	  $(XCB) -scheme "$(TEST_SCHEME)" $(QUIET) $(UNSIGNED_FLAGS) test; \
	else \
	  echo "No test scheme set: the repo has no unit tests yet (plan phase P1)."; \
	  echo "Add a test target, then run: make test TEST_SCHEME=<scheme>"; \
	fi

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
	@echo "== app";  codesign -d --entitlements :- "$(APP_PATH)" 2>&1 || true
	@for e in "$(APP_PATH)"/Contents/Library/SystemExtensions/*.systemextension; do [ -e "$$e" ] || continue; echo "== $$e"; codesign -d --entitlements :- "$$e" 2>&1 || true; done

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
	@if [ "$(CONFIRM)" = 1 ]; then git clean -fdX; else echo "Dry run (add CONFIRM=1 to delete):"; git clean -ndX; fi
