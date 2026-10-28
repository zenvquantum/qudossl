# QudoSSL top-level build wrapper
#
#   make -C build            build everything
#   make -C build qudo-pqc   stage 1 only (libqudo-pqc.a)
#   make -C build openssl    stage 2 only (libcrypto.so, libssl.so, fips.so)
#   make -C build test       run the OpenSSL test suite
#   make -C build clean      remove build outputs
#   make -C build help       list targets
#
# Two stages:
#   1. CMake builds qudo-pqc-lib/ into libqudo-pqc.a (math-only)
#   2. OpenSSL is configured and built from openssl/
#
# Stage 2 configures OpenSSL against stage 1's archive, so crypto/ml_kem and
# crypto/ml_dsa delegate to qudo-pqc. The archive is linked statically so the
# FIPS module's integrity check covers the PQC math.

SHELL := /bin/bash
REPO_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))..)
OPENSSL_DIR := $(REPO_ROOT)/openssl
QUDO_PQC_DIR := $(REPO_ROOT)/qudo-pqc-lib
QUDO_PQC_BUILD := $(QUDO_PQC_DIR)/build
QUDO_PQC_ARCHIVE := $(QUDO_PQC_BUILD)/lib/libqudo-pqc.a
# Full (non-math-only) build of qudo-pqc-lib for its own test suite, kept
# separate from the math-only archive used by stage 2.
QUDO_PQC_TEST_BUILD := $(QUDO_PQC_DIR)/build-standalone-test

# ---- configuration knobs ----------------------------------------------------
FIPS ?= yes
JOBS ?= $(shell (command -v nproc >/dev/null && nproc) || sysctl -n hw.ncpu || echo 4)
PREFIX ?= $(REPO_ROOT)/build/out

# Fixed SOURCE_DATE_EPOCH for reproducible builds.
SOURCE_DATE_EPOCH ?= 1752451200
export SOURCE_DATE_EPOCH

# ---- platform detection -----------------------------------------------------
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

ifeq ($(UNAME_S),Linux)
  ifeq ($(UNAME_M),x86_64)
    OPENSSL_TARGET ?= linux-x86_64
  else ifneq (,$(filter $(UNAME_M),aarch64 arm64))
    OPENSSL_TARGET ?= linux-aarch64
  else
    OPENSSL_TARGET ?= linux-generic64
  endif
  # --build-id=none for reproducibility. -z noexecstack because
  # keccak1600-x86_64.s.o lacks a .note.GNU-stack marker, which would otherwise
  # give the module an executable stack.
  REPRO_LDFLAGS ?= -Wl,--build-id=none -Wl,-z,noexecstack
else ifeq ($(UNAME_S),Darwin)
  ifeq ($(UNAME_M),arm64)
    OPENSSL_TARGET ?= darwin64-arm64-cc
  else
    OPENSSL_TARGET ?= darwin64-x86_64-cc
  endif
  # -Wl,-no_uuid is not used: ld refuses to link against a dylib without
  # LC_UUID. Determinism on macOS comes from:
  #   ZERO_AR_DATE=1  zero the timestamps ar/libtool embed in static archives
  #   LC_UUID         ld64 derives the UUID from a content hash, so identical
  #                   inputs produce an identical UUID -- no stripping needed
  #   -ffile-prefix-map  keep absolute build paths out of the binaries
  REPRO_LDFLAGS ?=
  export ZERO_AR_DATE := 1
else
  OPENSSL_TARGET ?= cc
  REPRO_LDFLAGS ?=
endif

REPRO_CFLAGS ?= -ffile-prefix-map=$(REPO_ROOT)=.

ifeq ($(FIPS),yes)
  FIPS_FLAG := enable-fips
else
  FIPS_FLAG :=
endif

CONFIG_STAMP := $(OPENSSL_DIR)/configdata.pm

.PHONY: all qudo-pqc openssl openssl-config test test-pqc install install_sw clean distclean repro-check help

# Sub-makes rather than prerequisites, so the two stages stay ordered even
# under -j: stage 2 consumes stage 1's archive.
all:
	@$(MAKE) --no-print-directory qudo-pqc
	@$(MAKE) --no-print-directory openssl

help:
	@echo "QudoSSL build wrapper"
	@echo "  target platform : $(OPENSSL_TARGET)"
	@echo "  fips            : $(FIPS)"
	@echo "  jobs            : $(JOBS)"
	@echo ""
	@echo "  all           build stage 1 + stage 2"
	@echo "  qudo-pqc      stage 1 only -> libqudo-pqc.a"
	@echo "  openssl       stage 2 only -> libcrypto.so, libssl.so"
	@echo "  test          run the OpenSSL test suite"
	@echo "  test-pqc      run qudo-pqc-lib's own test suite"
	@echo "  repro-check   build twice, compare hashes"
	@echo "  install       install into PREFIX ($(PREFIX))"
	@echo "  clean         remove build outputs"
	@echo "  distclean     clean + remove OpenSSL configuration"

# ---- stage 1 ----------------------------------------------------------------
# Always run CMake, which does its own up-to-date checking of qudo-pqc-lib
# sources.
qudo-pqc:
	@JOBS=$(JOBS) $(REPO_ROOT)/build/build_libqudo_pqc.sh

# ---- stage 2 ----------------------------------------------------------------
openssl-config: check-prefix $(CONFIG_STAMP)

# PREFIX is recorded in configdata.pm by Configure; reconfigure if it changed.
.PHONY: check-prefix
check-prefix:
	@if [ -f "$(CONFIG_STAMP)" ] \
	   && ! grep -q '"prefix" => "$(PREFIX)"' "$(CONFIG_STAMP)" 2>/dev/null; then \
	    echo "==> PREFIX changed to $(PREFIX) -- reconfiguring"; \
	    rm -f "$(CONFIG_STAMP)"; \
	fi


$(CONFIG_STAMP): $(QUDO_PQC_ARCHIVE)
	@echo "==> Stage 2: configuring OpenSSL ($(OPENSSL_TARGET), fips=$(FIPS))"
	cd $(OPENSSL_DIR) && ./Configure $(OPENSSL_TARGET) $(FIPS_FLAG) \
	    --prefix=$(PREFIX) \
	    --libdir=lib \
	    --with-qudo-pqc-archive=$(QUDO_PQC_ARCHIVE) \
	    --with-qudo-pqc-include=$(QUDO_PQC_DIR)/include \
	    --with-qudo-pqc-include=$(QUDO_PQC_DIR)/qudo-mlkem/include \
	    --with-qudo-pqc-include=$(QUDO_PQC_DIR)/qudo-mldsa/include \
	    $(REPRO_CFLAGS) \
	    $(REPRO_LDFLAGS) \
	    $(OPENSSL_EXTRA_FLAGS)

openssl: openssl-config
	@echo "==> Stage 2: building OpenSSL"
	$(MAKE) -C $(OPENSSL_DIR) -j$(JOBS)
	@echo "==> Build complete:"
	@ls -1 $(OPENSSL_DIR)/libcrypto.*[ao] $(OPENSSL_DIR)/libcrypto.*dylib \
	       $(OPENSSL_DIR)/libssl.*[ao] $(OPENSSL_DIR)/libssl.*dylib 2>/dev/null || true
# Explicit names: a fips.* glob would also match fips.checksum and
# fips.module.sources, which are sources, not build outputs.
	@ls -1 $(OPENSSL_DIR)/providers/fips.so $(OPENSSL_DIR)/providers/fips.dylib \
	       $(OPENSSL_DIR)/providers/fips.dll 2>/dev/null || true

# ---- tests ------------------------------------------------------------------
test: all
	$(MAKE) -C $(OPENSSL_DIR) test HARNESS_JOBS=$(JOBS)

# Runs qudo-pqc-lib's own test suite against its full build; some of its tests
# need the FIPS services that the math-only archive omits.
test-pqc:
	cmake -S $(QUDO_PQC_DIR) -B $(QUDO_PQC_TEST_BUILD) \
	    -DCMAKE_BUILD_TYPE=Release \
	    -DBUILD_SHARED_LIBS=OFF \
	    -DQUDO_PQC_BUILD_TESTS=ON
	cmake --build $(QUDO_PQC_TEST_BUILD) --parallel $(JOBS)
	cd $(QUDO_PQC_TEST_BUILD) && ctest --output-on-failure

# ---- reproducibility --------------------------------------------------------
repro-check:
	@$(REPO_ROOT)/reproducible-build/verify-reproducible.sh

# ---- install ----------------------------------------------------------------
# Installs OpenSSL into $(PREFIX). The FIPS module is installed as
# $(PREFIX)/lib/ossl-modules/fips.*, as upstream does.
install: openssl
	$(MAKE) -C $(OPENSSL_DIR) install DESTDIR=$(DESTDIR)
	@$(MAKE) --no-print-directory install-cli-name
	@echo "==> Installed to $(PREFIX)"
	@echo "    Run 'qudossl fipsinstall' to generate fipsmodule.cnf for the module."

install_sw: openssl
	$(MAKE) -C $(OPENSSL_DIR) install_sw DESTDIR=$(DESTDIR)
	@$(MAKE) --no-print-directory install-cli-name

# Installs the `qudossl` wrapper next to the `openssl` binary.
#
#   openssl  the OpenSSL binary, with upstream behaviour and version output.
#   qudossl  prints the QudoSSL banner on `version` and otherwise runs openssl.
.PHONY: install-cli-name
install-cli-name:
	@bindir="$(DESTDIR)$(PREFIX)/bin"; \
	if [ ! -x "$$bindir/openssl" ]; then \
	    echo "install-cli-name: no openssl at $$bindir -- did PREFIX change without a reconfigure?" >&2; \
	    exit 1; \
	fi; \
	install -m 755 "$(REPO_ROOT)/build/qudossl" "$$bindir/qudossl"; \
	echo "==> CLI: openssl (binary) + qudossl (wrapper) installed in $$bindir"

# ---- release ----------------------------------------------------------------
# The source tarball is created from git HEAD, not the working tree. The
# version is read from QUDO_PRODUCT_VERSION in build/qudossl.
DIST_VERSION := $(shell sed -n 's/^QUDO_PRODUCT_VERSION="\(.*\)"/\1/p' $(REPO_ROOT)/build/qudossl)
DIST_NAME    := qudossl-$(DIST_VERSION)
DIST_DIR     := $(REPO_ROOT)/dist
SOURCE_EPOCH := $(shell git -C $(REPO_ROOT) log -1 --format=%ct 2>/dev/null || echo 0)

.PHONY: dist dist-verify

dist:
	@test -n "$(DIST_VERSION)" || \
	  { echo "dist: cannot read QUDO_PRODUCT_VERSION from build/qudossl" >&2; exit 1; }
	@if tag=$$(git -C $(REPO_ROOT) describe --tags --exact-match 2>/dev/null); then \
	  if [ "$$tag" != "$(DIST_NAME)" ]; then \
	    echo "dist: HEAD tag '$$tag' != '$(DIST_NAME)' (from the wrapper's QUDO_PRODUCT_VERSION)" >&2; \
	    exit 1; fi; \
	else \
	  echo "==> note: HEAD is untagged — building a SNAPSHOT (tag $(DIST_NAME) for a release)"; \
	fi
	@echo "==> staging $(DIST_NAME) from git HEAD"
	@rm -rf "$(DIST_DIR)/$(DIST_NAME)" && mkdir -p "$(DIST_DIR)/$(DIST_NAME)"
	git -C $(REPO_ROOT) archive --format=tar HEAD | tar -x -C "$(DIST_DIR)/$(DIST_NAME)"
	@echo "==> normalising timestamps to the HEAD commit date"
	@stamp=$$(perl -e '@t = gmtime($(SOURCE_EPOCH)); \
	  printf "%04d%02d%02d%02d%02d.%02d", $$t[5]+1900, $$t[4]+1, $$t[3], $$t[2], $$t[1], $$t[0]'); \
	TZ=UTC find "$(DIST_DIR)/$(DIST_NAME)" -exec touch -t "$$stamp" {} +
	@echo "==> packing $(DIST_NAME)-src.tar.gz"
	@if tar --version 2>/dev/null | grep -q GNU; then \
	  tar --sort=name --owner=0 --group=0 --numeric-owner \
	      -C "$(DIST_DIR)" -czf "$(DIST_DIR)/$(DIST_NAME)-src.tar.gz" "$(DIST_NAME)"; \
	else \
	  (cd "$(DIST_DIR)" && find "$(DIST_NAME)" | sort | \
	    COPYFILE_DISABLE=1 tar -czf "$(DIST_NAME)-src.tar.gz" --uid 0 --gid 0 -n -T -); \
	fi
	@(cd "$(DIST_DIR)" && shasum -a 256 "$(DIST_NAME)-src.tar.gz" > "$(DIST_NAME)-src.tar.gz.sha256")
	@rm -rf "$(DIST_DIR)/$(DIST_NAME)"
	@echo "==> $(DIST_DIR)/$(DIST_NAME)-src.tar.gz"
	@cat "$(DIST_DIR)/$(DIST_NAME)-src.tar.gz.sha256"

# Builds, installs and checks the release tarball.
dist-verify:
	@bash "$(REPO_ROOT)/build/dist-verify.sh" "$(DIST_DIR)/$(DIST_NAME)-src.tar.gz"

# ---- housekeeping -----------------------------------------------------------
clean:
	-$(MAKE) -C $(OPENSSL_DIR) clean 2>/dev/null
	rm -rf $(QUDO_PQC_BUILD)
	rm -rf $(QUDO_PQC_TEST_BUILD)
	rm -rf $(PREFIX)

distclean: clean
	-$(MAKE) -C $(OPENSSL_DIR) distclean 2>/dev/null
	rm -f $(CONFIG_STAMP)
