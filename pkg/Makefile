# Variables required for this Makefile
PKG_DIR = $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
TOP_DIR = $(PKG_DIR)/../bin
BUILD_DIR = $(PKG_DIR)/build
TARGET_DIR = $(PKG_DIR)/target
CONFIG_DIR = /etc/aerospike
DOC_DIR = /opt/aerospike/doc/$(PACKAGE_NAME)
MAC_DOC_DIR = /usr/local/aerospike/doc/$(PACKAGE_NAME)
# Package variables
PACKAGE_NAME = asbackup
VERSION ?= $(shell git describe --tags --always --abbrev=9)
# Package names never carry the "rcN" pre-release tag: rcN becomes the package
# iteration, so 4.5.9-rc2 packages as version 4.5.9 iteration 2.
PKG_RELEASE_SH = $(PKG_DIR)/../.github/bin/pkg_release.sh
PKG_VERSION := $(shell $(PKG_RELEASE_SH) '$(VERSION)' version)
ITERATION := $(or $(ITERATION),$(shell $(PKG_RELEASE_SH) '$(VERSION)' iteration))
# For names with no iteration field of their own (.tar, macOS .pkg).
RELEASE := $(PKG_VERSION)-$(ITERATION)
RPM_VERSION := $(subst -,_,$(PKG_VERSION))
# rpm Release / deb revision. The deb revision embeds the distro per Debian
# convention (e.g. 4.5.8-1debian12), like the rpm dist tag.
DEB_ITERATION := $(ITERATION)$(BUILD_DISTRO)
BUILD_DISTRO ?= $(shell $(PKG_DIR)/../.github/bin/os_version.sh)
# ubuntu26.04 only (BUILD_DISTRO substring match): binaries link libjitterentropy; declare runtime dep.
DEB_EXTRA_DEPENDS :=
ifneq (,$(findstring ubuntu26.04,$(BUILD_DISTRO)))
  DEB_EXTRA_DEPENDS := --depends "libjitterentropy3"
endif
NAME = "aerospike-$(PACKAGE_NAME)"
MAINTAINER = "Aerospike"
DESCRIPTION = "ASBackup, a tool for backing up and restoring data for Aerospike database."
LICENSE = "Apache License 2.0"
URL = "https://github.com/aerospike/aerospike-tools-backup"
VENDOR = "Aerospike, Inc."
ARCH = $(shell uname -m)
# pkgbuild --version rejects hyphens and underscores; collapse both to dots
# (4.5.8-1 -> 4.5.8.1), and defensively normalize any underscore-form
# inputs (env overrides) too. This is the version *inside* the pkg only;
# the file name below keeps the canonical hyphenated RELEASE.
MAC_VERSION := $(subst _,.,$(subst -,.,$(RELEASE)))
MAC_ROOT = $(BUILD_DIR)/mac-root
PKG_ID = com.aerospike.asbackup
# macOS artifact file name, lower case and '-' separated so a Homebrew cask can
# interpolate it (<arch> is `uname -m`, the token a cask's `arch` stanza emits):
#
#     aerospike-asbackup-<version>-<iteration>-macos<major>-<arch>.pkg
#
# macos<major> is the generation the artifact was BUILT on, not a minimum it
# supports; it keeps one release's per-runner artifacts distinct. MAC_PLATFORM
# is `:=` so check-version's guard tests the token that lands in the name.
MAC_PLATFORM := $(shell $(PKG_DIR)/../.github/bin/os_version.sh)
MAC_PKG = $(TARGET_DIR)/aerospike-asbackup-$(RELEASE)-$(MAC_PLATFORM)-$(ARCH).pkg


.PHONY: all
all: deb rpm tar

.PHONY: deb
deb: prep
	fpm --force \
		--config-files $(CONFIG_DIR) \
		--input-type dir \
		--output-type deb \
		--chdir $(BUILD_DIR)/ \
		--name $(NAME) \
		--version $(PKG_VERSION) \
		--iteration $(DEB_ITERATION) \
		--maintainer $(MAINTAINER) \
		$(DEB_EXTRA_DEPENDS) \
		--description $(DESCRIPTION) \
		--license $(LICENSE) \
		--url $(URL) \
		--vendor $(VENDOR) \
		--after-install $(PKG_DIR)/postinst.sh \
		--after-upgrade $(PKG_DIR)/postinst.sh \
		--package $(TARGET_DIR)/$(NAME)_$(PKG_VERSION)-$(DEB_ITERATION)_$(ARCH).deb

.PHONY: rpm
rpm: prep
	fpm --force \
		--rpm-rpmbuild-define '_build_id_links none' \
		--exclude 'usr/lib/.build-id/*' \
		--exclude 'usr/lib64/*' \
		--config-files $(CONFIG_DIR) \
		--input-type dir \
		--output-type rpm \
		--chdir $(BUILD_DIR)/ \
		--name $(NAME) \
		--version $(RPM_VERSION) \
		--iteration $(ITERATION) \
		--maintainer $(MAINTAINER) \
		--depends "openssl-libs" \
		--description $(DESCRIPTION) \
		--license $(LICENSE) \
		--url $(URL) \
		--vendor $(VENDOR) \
		--after-install $(PKG_DIR)/postinst.sh \
		--after-upgrade $(PKG_DIR)/postinst.sh \
		--package $(TARGET_DIR)/$(NAME)-$(RPM_VERSION)-$(ITERATION).$(BUILD_DISTRO).$(ARCH).rpm

.PHONY: tar
tar: prep
	fpm --force \
		--config-files $(CONFIG_DIR) \
		--input-type dir \
		--output-type tar \
		--chdir $(BUILD_DIR)/ \
		--name $(NAME) \
		--version $(PKG_VERSION) \
		--maintainer $(MAINTAINER) \
		--description $(DESCRIPTION) \
		--license $(LICENSE) \
		--url $(URL) \
		--vendor $(VENDOR) \
		--package $(TARGET_DIR)/$(NAME)-$(RELEASE)-$(BUILD_DISTRO)-$(ARCH).tar

# $(shell ...) discards the exit status, so a pkg_release.sh that cannot run
# (missing, non-executable, empty VERSION) yields empty strings and the build
# would silently emit aerospike-asbackup_-1ubuntu24.04_x86_64.deb rather than
# fail. Guard the version tokens the way prep-mac already guards the platform.
.PHONY: check-version
check-version:
	@test -n '$(VERSION)' && test '$(VERSION)' != 'unknown' \
		|| { echo "ERROR: VERSION is '$(VERSION)' -- git describe failed and none was passed; refusing to build an unversioned package" >&2; exit 1; }
	@test -n "$(PKG_VERSION)" || { echo "ERROR: empty PKG_VERSION -- $(PKG_RELEASE_SH) failed for VERSION='$(VERSION)'; refusing to build an unversioned package" >&2; exit 1; }
	@test -n "$(ITERATION)" || { echo "ERROR: empty ITERATION -- $(PKG_RELEASE_SH) failed for VERSION='$(VERSION)'; refusing to build an unversioned package" >&2; exit 1; }

.PHONY: prep
prep: check-version
	install -d $(TARGET_DIR)
	install -d $(BUILD_DIR)/$(CONFIG_DIR)
	install -d $(BUILD_DIR)/opt/aerospike/bin
	install -pm 755 $(TOP_DIR)/asbackup $(BUILD_DIR)/opt/aerospike/bin
	install -pm 755 $(TOP_DIR)/asrestore $(BUILD_DIR)/opt/aerospike/bin
	install -d $(BUILD_DIR)/usr/bin
	ln -sf /opt/aerospike/bin/asbackup $(BUILD_DIR)/usr/bin/asbackup
	ln -sf /opt/aerospike/bin/asrestore $(BUILD_DIR)/usr/bin/asrestore
	install -d $(BUILD_DIR)$(DOC_DIR)
	install -pm 644 $(PKG_DIR)/astools.conf.sample $(BUILD_DIR)$(DOC_DIR)/astools.conf.sample

# Staging for macOS installer: install to /usr/local/aerospike/bin with symlinks at /usr/local/bin.
.PHONY: prep-mac
prep-mac: check-version
	@test -n "$(MAC_PLATFORM)" || { echo "ERROR: empty macOS platform token -- .github/bin/os_version.sh failed; refusing to build an unnamed pkg" >&2; exit 1; }
	install -d $(TARGET_DIR)
	rm -rf $(MAC_ROOT)
	install -d $(MAC_ROOT)/usr/local/aerospike/bin
	install -d $(MAC_ROOT)/usr/local/bin
	install -pm 755 $(TOP_DIR)/asbackup $(MAC_ROOT)/usr/local/aerospike/bin/asbackup
	install -pm 755 $(TOP_DIR)/asrestore $(MAC_ROOT)/usr/local/aerospike/bin/asrestore
	ln -sf ../aerospike/bin/asbackup $(MAC_ROOT)/usr/local/bin/asbackup
	ln -sf ../aerospike/bin/asrestore $(MAC_ROOT)/usr/local/bin/asrestore
	install -d $(MAC_ROOT)$(MAC_DOC_DIR)
	install -pm 644 $(PKG_DIR)/astools.conf.sample $(MAC_ROOT)$(MAC_DOC_DIR)/astools.conf.sample

.PHONY: osx-pkg
osx-pkg: prep-mac
	pkgbuild \
		--root $(MAC_ROOT) \
		--identifier $(PKG_ID) \
		--version $(MAC_VERSION) \
		--install-location / \
		--scripts $(PKG_DIR)/mac-scripts \
		$(MAC_PKG)

.PHONY: clean
clean:
	rm -rf $(TARGET_DIR)
	rm -rf $(BUILD_DIR)/opt
	rm -rf $(BUILD_DIR)/var
	rm -rf $(MAC_ROOT)
