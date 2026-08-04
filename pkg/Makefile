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
RPM_VERSION := $(subst -,_,$(VERSION))
# rpm Release / deb revision. The deb revision embeds the distro per Debian
# convention (e.g. 5.0.3-1debian12), like the rpm dist tag.
ITERATION ?= 1
DEB_ITERATION = $(ITERATION)$(BUILD_DISTRO)
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
# pkgbuild rejects '-' and '_' in --version; normalize pre-release tags to '.' (see CI .pkg rename).
MAC_VERSION := $(subst _,.,$(subst -,.,$(VERSION)))
MAC_ROOT = $(BUILD_DIR)/mac-root
PKG_ID = com.aerospike.asbackup
MAC_PKG = $(TARGET_DIR)/aerospike-asbackup-$(MAC_VERSION)-$(ARCH).pkg


.PHONY: all
all: deb rpm tar

# The aerospike-tools bundle ships these same /opt/aerospike/bin paths. deb
# Replaces (without Conflicts) lets dpkg hand file ownership to this package;
# rpm has no equivalent, so Conflicts turns an opaque file-conflict error into
# an actionable one.
.PHONY: deb
deb: prep
	fpm --force \
		--config-files $(CONFIG_DIR) \
		--input-type dir \
		--output-type deb \
		--chdir $(BUILD_DIR)/ \
		--name $(NAME) \
		--version $(VERSION) \
		--iteration $(DEB_ITERATION) \
		--maintainer $(MAINTAINER) \
		$(DEB_EXTRA_DEPENDS) \
		--description $(DESCRIPTION) \
		--license $(LICENSE) \
		--url $(URL) \
		--vendor $(VENDOR) \
		--after-install $(PKG_DIR)/postinst.sh \
		--after-upgrade $(PKG_DIR)/postinst.sh \
		--replaces "aerospike-tools" \
		--package $(TARGET_DIR)/$(NAME)_$(VERSION)-$(DEB_ITERATION)_$(ARCH).deb

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
		--conflicts "aerospike-tools" \
		--package $(TARGET_DIR)/$(NAME)-$(RPM_VERSION)-$(ITERATION).$(BUILD_DISTRO).$(ARCH).rpm

.PHONY: tar
tar: prep
	fpm --force \
		--config-files $(CONFIG_DIR) \
		--input-type dir \
		--output-type tar \
		--chdir $(BUILD_DIR)/ \
		--name $(NAME) \
		--version $(VERSION) \
		--maintainer $(MAINTAINER) \
		--description $(DESCRIPTION) \
		--license $(LICENSE) \
		--url $(URL) \
		--vendor $(VENDOR) \
		--package $(TARGET_DIR)/$(NAME)-$(BUILD_DISTRO)-$(VERSION)-$(ARCH).tar

.PHONY: prep
prep:
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
prep-mac:
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
