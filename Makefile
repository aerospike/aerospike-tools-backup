#
# Aerospike Backup/Restore
#
# Copyright (c) 2008-2017 Aerospike, Inc. All rights reserved.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

# deprecated: support for explicit client repo
ifdef CLIENTREPO
$(warning Setting CLIENTREPO explicitly is deprecated, the c-client is now a submodule of asbackup)
DIR_C_CLIENT := $(CLIENTREPO)
endif

OS := $(shell uname -s)
ARCH := $(shell uname -m)
PLATFORM := $(OS)-$(ARCH)
VERSION := $(shell git describe 2>/dev/null; if [ $${?} != 0 ]; then echo 'unknown'; fi)
ROOT = $(CURDIR)

CC ?= cc

DWARF := $(shell $(CC) -Wall -Wextra -O2 -o /tmp/asflags_$${$$} src/flags.c; \
		/tmp/asflags_$${$$}; rm /tmp/asflags_$${$$})
CFLAGS += -std=gnu99 $(DWARF) -O0 -march=nocona -fno-common -fno-strict-aliasing \
		-Wall -Wextra -Wconversion -Wsign-conversion -Wmissing-declarations \
		-Wno-implicit-fallthrough -Wno-unused-result -Wno-typedef-redefinition \
		-D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=2 -DMARCH_$(ARCH) \
		-DTOOL_VERSION=\"$(VERSION)\"
CXXFLAGS := -std=c++14 $(DWARF) -O0 -march=nocona -fno-common -fno-strict-aliasing \
		-Wall -Wextra -Wconversion -Wsign-conversion -Wmissing-declarations \
		-Wno-implicit-fallthrough -Wno-unused-result \
		-D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=2 -DMARCH_$(ARCH) \
		-DTOOL_VERSION=\"$(VERSION)\"

LD := $(CC)
LDFLAGS += $(CXXFLAGS)

ifeq ($(OS), Linux)
LDFLAGS += -pthread
endif

TEST_CFLAGS := -std=gnu99 $(DWARF) -g -O2 -march=nocona -fno-common -fno-strict-aliasing \
		-Wall -Wextra -Wconversion -Wsign-conversion -Wmissing-declarations \
		-Wno-implicit-fallthrough -Wno-unused-result -Wno-typedef-redefinition \
		-D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=2 -DMARCH_$(ARCH) \
		-DTOOL_VERSION=\"$(VERSION)\"
TEST_CXXFLAGS := -std=c++14 $(DWARF) -g -O2 -march=nocona -fno-common -fno-strict-aliasing \
		-Wall -Wextra -Wconversion -Wsign-conversion -Wmissing-declarations \
		-Wno-implicit-fallthrough -Wno-unused-result \
		-D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=2 -DMARCH_$(ARCH) \
		-DTOOL_VERSION=\"$(VERSION)\"
TEST_LDFLAGS := $(LDFLAGS) -fprofile-arcs -lcheck

ifeq ($(EVENT_LIB),libev)
  CFLAGS += -DAS_USE_LIBEV
  CXXFLAGS += -DAS_USE_LIBEV
  TEST_CFLAGS += -DAS_USE_LIBEV
  TEST_CXXFLAGS += -DAS_USE_LIBEV
endif

ifeq ($(EVENT_LIB),libuv)
  CFLAGS += -DAS_USE_LIBUV
  CXXFLAGS += -DAS_USE_LIBUV
  TEST_CFLAGS += -DAS_USE_LIBUV
  TEST_CXXFLAGS += -DAS_USE_LIBUV
endif

ifeq ($(EVENT_LIB),libevent)
  CFLAGS += -DAS_USE_LIBEVENT
  CXXFLAGS += -DAS_USE_LIBEVENT
  TEST_CFLAGS += -DAS_USE_LIBEVENT
  TEST_CXXFLAGS += -DAS_USE_LIBEVENT
endif

DIR_INC := $(ROOT)/include
DIR_SRC := $(ROOT)/src
DIR_OBJ := $(ROOT)/obj
DIR_MODULES := $(ROOT)/modules
DIR_UNIT_TEST := $(ROOT)/test/unit
DIR_TEST_BIN := $(ROOT)/test_target
DIR_TEST_OBJ := $(DIR_TEST_BIN)/obj
DIR_INTEGRATION_TEST := $(ROOT)/test/integration
DIR_BIN := $(ROOT)/bin
DIR_LIB := $(ROOT)/lib
DIR_DOCS := $(ROOT)/docs
DIR_ENV := $(ROOT)/env
DIR_TOML := $(ROOT)/src/toml

DIR_C_CLIENT ?= $(DIR_MODULES)/c-client
C_CLIENT_LIB := $(DIR_C_CLIENT)/target/$(PLATFORM)/lib/libaerospike.a

INCLUDES := -I$(DIR_INC)
INCLUDES += -I$(DIR_TOML)
INCLUDES += -I$(DIR_C_CLIENT)/src/include
INCLUDES += -I$(DIR_C_CLIENT)/modules/common/src/include
INCLUDES += -I/usr/local/opt/openssl/include

LIBRARIES := $(C_CLIENT_LIB)
LIBRARIES += -L/usr/local/lib

ifeq ($(AWS_SDK_STATIC_PATH),)
  LIBRARIES += -laws-cpp-sdk-s3
  LIBRARIES += -laws-cpp-sdk-core
else
  # do not change the order of these
  LIBRARIES += $(AWS_SDK_STATIC_PATH)/libaws-cpp-sdk-s3.a
  LIBRARIES += $(AWS_SDK_STATIC_PATH)/libaws-cpp-sdk-core.a
  LIBRARIES += $(AWS_SDK_STATIC_PATH)/libaws-crt-cpp.a
  LIBRARIES += $(AWS_SDK_STATIC_PATH)/libaws-c-s3.a
  LIBRARIES += $(AWS_SDK_STATIC_PATH)/libaws-c-auth.a
  LIBRARIES += $(AWS_SDK_STATIC_PATH)/libaws-c-mqtt.a
  LIBRARIES += $(AWS_SDK_STATIC_PATH)/libaws-c-http.a
  LIBRARIES += $(AWS_SDK_STATIC_PATH)/libaws-c-event-stream.a
  LIBRARIES += $(AWS_SDK_STATIC_PATH)/libaws-c-io.a
  LIBRARIES += $(AWS_SDK_STATIC_PATH)/libaws-c-compression.a
  LIBRARIES += $(AWS_SDK_STATIC_PATH)/libaws-checksums.a
  LIBRARIES += $(AWS_SDK_STATIC_PATH)/libaws-c-cal.a
  ifeq ($(OS),Linux)
    LIBRARIES += $(AWS_SDK_STATIC_PATH)/libs2n.a
  endif
  LIBRARIES += $(AWS_SDK_STATIC_PATH)/libaws-c-common.a

  ifeq ($(OS),Darwin)
    LIBRARIES += -framework CoreFoundation -framework Security
  endif

  ifeq ($(CURL_STATIC_PATH),)
    LIBRARIES += -lcurl
  else
    LIBRARIES += $(CURL_STATIC_PATH)/libcurl.a

    ifeq ($(OS),Darwin)
      LIBRARIES += -framework SystemConfiguration

      ifeq ($(LIBSSH2_STATIC_PATH),)
        LIBRARIES += -lssh2
      else
        LIBRARIES += $(LIBSSH2_STATIC_PATH)/libssh2.a
      endif
    endif
  endif
endif

ifeq ($(OPENSSL_STATIC_PATH),)
  LIBRARIES += -L/usr/local/opt/openssl/lib
  LIBRARIES += -lssl
  LIBRARIES += -lcrypto
else
  LIBRARIES += $(OPENSSL_STATIC_PATH)/libssl.a
  LIBRARIES += $(OPENSSL_STATIC_PATH)/libcrypto.a
endif
LIBRARIES += -lpthread
LIBRARIES += -lm

ifeq ($(ZLIB_STATIC_PATH),)
  LIBRARIES += -lz
else
  LIBRARIES += $(ZLIB_STATIC_PATH)/libz.a
endif

ifeq ($(ZSTD_STATIC_PATH),)
  LIBRARIES += -lzstd
else
  LIBRARIES += $(ZSTD_STATIC_PATH)/libzstd.a
endif

ifeq ($(EVENT_LIB),libev)
  ifeq ($(LIBEV_STATIC_PATH),)
    LIBRARIES += -lev
  else
    LIBRARIES += $(LIBEV_STATIC_PATH)/libev.a
  endif
endif

ifeq ($(EVENT_LIB),libuv)
  ifeq ($(LIBUV_STATIC_PATH),)
    LIBRARIES += -luv
  else
    LIBRARIES += $(LIBUV_STATIC_PATH)/libuv.a
  endif
endif

ifeq ($(EVENT_LIB),libevent)
  ifeq ($(LIBEVENT_STATIC_PATH),)
    LIBRARIES += -levent_core -levent_pthreads
  else
    LIBRARIES += $(LIBEVENT_STATIC_PATH)/libevent_core.a $(LIBEVENT_STATIC_PATH)/libevent_pthreads.a
  endif
endif


ifeq ($(OS), Linux)
LIBRARIES += -ldl -lrt
LIBRARIES += -L$(DIR_TOML) -Wl,-l,:libtoml.a
else
LIBRARIES += $(DIR_TOML)/libtoml.a
endif

src_to_obj = $(filter $(DIR_OBJ)/%.o,$(1:$(DIR_SRC)/%.c=$(DIR_OBJ)/%_c.o) $(1:$(DIR_SRC)/%.cc=$(DIR_OBJ)/%_cc.o))
obj_to_dep = $(1:%.o=%.d)
src_to_lib =

BACKUP_SRC_MAIN := $(DIR_SRC)/backup_main.c
RESTORE_SRC_MAIN := $(DIR_SRC)/restore_main.c
FLAGS_SRC_MAIN := $(DIR_SRC)/flags.c
TOML_SRC_MAIN := $(DIR_SRC)/toml/toml.c
HELPER_SRCS := $(filter-out $(BACKUP_SRC_MAIN) $(RESTORE_SRC_MAIN) \
	$(FLAGS_SRC_MAIN) $(TOML_SRC_MAIN),\
	$(shell find $(DIR_SRC) -name '*.c' -type f))
HELPER_CXX_SRCS := $(filter-out $(BACKUP_SRC_MAIN) $(RESTORE_SRC_MAIN) \
	$(FLAGS_SRC_MAIN) $(TOML_SRC_MAIN),\
	$(shell find $(DIR_SRC) -name '*.cc' -type f))

BACKUP_SRC := $(BACKUP_SRC_MAIN) $(HELPER_SRCS) $(HELPER_CXX_SRCS)
BACKUP_OBJ := $(call src_to_obj, $(BACKUP_SRC))
BACKUP_DEP := $(call obj_to_dep, $(BACKUP_OBJ))

RESTORE_SRC := $(RESTORE_SRC_MAIN) $(HELPER_SRCS) $(HELPER_CXX_SRCS)
RESTORE_OBJ := $(call src_to_obj, $(RESTORE_SRC))
RESTORE_DEP := $(call obj_to_dep, $(RESTORE_OBJ))

BACKUP := $(DIR_BIN)/asbackup
RESTORE := $(DIR_BIN)/asrestore
TOML := $(DIR_TOML)/libtoml.a

SRCS := $(BACKUP_SRC) $(RESTORE_SRC)
OBJS := $(BACKUP_OBJ) $(RESTORE_OBJ)
DEPS := $(BACKUP_DEP) $(RESTORE_DEP)
BINS := $(TOML) $(BACKUP) $(RESTORE)

# sort removes duplicates
SRCS := $(sort $(SRCS))
OBJS := $(sort $(OBJS))
DEPS := $(sort $(DEPS))


# test target
test_src_to_obj = $(filter $(DIR_TEST_OBJ)/src/%.o,$(1:$(DIR_SRC)/%.c=$(DIR_TEST_OBJ)/src/%_c.o) $(1:$(DIR_SRC)/%.cc=$(DIR_TEST_OBJ)/src/%_cc.o))
HELPER_OBJS := $(call test_src_to_obj, $(HELPER_SRCS) $(HELPER_CXX_SRCS))
TEST_SRC := $(shell find $(DIR_UNIT_TEST) -name '*.c' -type f)
TEST_OBJ := $(HELPER_OBJS) $(patsubst $(DIR_UNIT_TEST)/%.c,$(DIR_TEST_OBJ)/unit/%.o,$(TEST_SRC))
TEST_DEP := $(patsubst $(DIR_TEST_OBJ)/%.o,$(DIR_TEST_OBJ)/%.d,$(TEST_OBJ))

TEST_INTEGRATION_TESTS := $(patsubst $(DIR_INTEGRATION_TEST)/%.py,run_%,$(shell find $(DIR_INTEGRATION_TEST) -name 'test_*.py' -type f))

TEST_BACKUP_SRC := $(BACKUP_SRC_MAIN) $(HELPER_SRCS) $(HELPER_CXX_SRCS)
TEST_BACKUP_OBJ := $(call test_src_to_obj, $(TEST_BACKUP_SRC))
TEST_BACKUP_DEP := $(call obj_to_dep, $(TEST_BACKUP_OBJ))

TEST_RESTORE_SRC := $(RESTORE_SRC_MAIN) $(HELPER_SRCS) $(HELPER_CXX_SRCS)
TEST_RESTORE_OBJ := $(call test_src_to_obj, $(TEST_RESTORE_SRC))
TEST_RESTORE_DEP := $(call obj_to_dep, $(TEST_RESTORE_OBJ))

TEST_BACKUP := $(DIR_TEST_BIN)/asbackup
TEST_RESTORE := $(DIR_TEST_BIN)/asrestore

TEST_BINS := $(TEST_BACKUP) $(TEST_RESTORE)
TEST_OBJS := $(TEST_OBJ) $(TEST_BACKUP_OBJ) $(TEST_RESTORE_OBJ)
TEST_DEPS := $(TEST_DEP) $(TEST_BACKUP_DEP) $(TEST_RESTORE_DEP)

TEST_OBJS := $(sort $(TEST_OBJS))
TEST_DEPS := $(sort $(TEST_DEPS))

.PHONY: all
all: $(BINS)

.PHONY: clean
clean:
	$(MAKE) -C $(DIR_TOML) clean
	$(MAKE) -C $(DIR_C_CLIENT) clean
	rm -f $(DEPS) $(OBJS) $(BINS) $(TEST_OBJS) $(TEST_DEPS) $(TEST_BINS)
	if [ -d $(DIR_OBJ) ]; then rmdir $(DIR_OBJ); fi
	if [ -d $(DIR_BIN) ]; then rmdir $(DIR_BIN); fi
	if [ -d $(DIR_TEST_OBJ) ]; then rm -r $(DIR_TEST_OBJ); fi
	if [ -d $(DIR_TEST_BIN) ]; then rm -r $(DIR_TEST_BIN); fi
	if [ -d $(DIR_DOCS) ]; then rm -r $(DIR_DOCS); fi
	if [ -d $(DIR_ENV) ]; then rm -rf $(DIR_ENV); fi

.PHONY: info
info:
	@echo
	@echo "  ROOT:       " $(ROOT)
	@echo "  OS:         " $(OS)
	@echo "  ARCH:       " $(ARCH)
	@echo "  CLIENTREPO: " $(DIR_C_CLIENT)
	@echo "  WD:         " $(shell pwd)
	@echo
	@echo "  PATHS:"
	@echo "      source:     " $(DIR_SRC)
	@echo "      target:     " $(DIR_BIN)
	@echo "      includes:   " $(DIR_INC)
	@echo "      libraries:  " $(DIR_LIB)
	@echo
	@echo "  COMPILER:"
	@echo "      command:    " $(CC)
	@echo "      flags:      " $(CFLAGS)
	@echo
	@echo "  LINKER:"
	@echo "      command:    " $(LD)
	@echo "      flags:      " $(LDFLAGS)
	@echo

$(DIR_DOCS): $(OBJS) $(SRCS) README.md
	if [ ! -d $(DIR_DOCS) ]; then mkdir $(DIR_DOCS); fi
	doxygen doxyfile

$(DIR_OBJ):
	mkdir $(DIR_OBJ)

$(DIR_BIN):
	mkdir $(DIR_BIN)

$(DIR_OBJ)/%_c.o: $(DIR_SRC)/%.c | $(DIR_OBJ)
	$(CC) $(CFLAGS) -MMD -o $@ -c $(INCLUDES) $<

$(DIR_OBJ)/%_cc.o: $(DIR_SRC)/%.cc | $(DIR_OBJ)
	$(CXX) $(CXXFLAGS) -MMD -o $@ -c $(INCLUDES) $<

$(BACKUP): $(BACKUP_OBJ) $(TOML) $(C_CLIENT_LIB) | $(DIR_BIN)
	$(CXX) $(LDFLAGS) -o $(BACKUP) $(BACKUP_OBJ) $(LIBRARIES)

$(RESTORE): $(RESTORE_OBJ) $(TOML) $(C_CLIENT_LIB) | $(DIR_BIN)
	$(CXX) $(LDFLAGS) -o $(RESTORE) $(RESTORE_OBJ) $(LIBRARIES)

$(TOML):
	$(MAKE) -C $(DIR_TOML)

$(C_CLIENT_LIB):
	$(MAKE) -C $(DIR_C_CLIENT)

-include $(BACKUP_DEP)
-include $(RESTORE_DEP)

.PHONY: test
test: unit integration

.PHONY: unit
unit: $(DIR_TEST_BIN)/test
	@$<
	@#valgrind --tool=memcheck --leak-check=full --track-origins=yes --show-leak-kinds=all $<

.PHONY: integration
integration: $(TEST_INTEGRATION_TESTS)

run_%: $(TEST_BINS) FORCE | coverage-init
	@./tests.sh $(DIR_ENV) $(patsubst run_%,$(DIR_INTEGRATION_TEST)/%.py,$@)

FORCE:

$(DIR_TEST_BIN):
	mkdir $@

$(DIR_TEST_OBJ): | $(DIR_TEST_BIN)
	mkdir $@

$(DIR_TEST_OBJ)/unit: | $(DIR_TEST_OBJ)
	mkdir $@

$(DIR_TEST_OBJ)/src: | $(DIR_TEST_OBJ)
	mkdir $@

$(DIR_TEST_OBJ)/unit/%.o: test/unit/%.c | $(DIR_TEST_OBJ)/unit
	$(CC) $(TEST_CFLAGS) -MMD $(INCLUDES) -o $@ -c $<

$(DIR_TEST_OBJ)/src/%_c.o: src/%.c | $(DIR_TEST_OBJ)/src
	$(CC) $(TEST_CFLAGS) -MMD $(INCLUDES) -fprofile-arcs -ftest-coverage -o $@ -c $<

$(DIR_TEST_OBJ)/src/%_cc.o: src/%.cc | $(DIR_TEST_OBJ)/src
	$(CXX) $(TEST_CXXFLAGS) -MMD $(INCLUDES) -fprofile-arcs -ftest-coverage -o $@ -c $<

$(DIR_TEST_BIN)/test: $(TEST_OBJ) $(DIR_C_CLIENT)/target/$(PLATFORM)/lib/libaerospike.a $(TOML) | $(DIR_TEST_BIN)
	$(CXX) -o $@ $(TEST_OBJ) $(DIR_C_CLIENT)/target/$(PLATFORM)/lib/libaerospike.a $(TEST_LDFLAGS) $(LIBRARIES)

$(TEST_BACKUP): $(TEST_BACKUP_OBJ) $(TOML) $(C_CLIENT_LIB) | $(DIR_TEST_BIN)
	$(CXX) $(TEST_LDFLAGS) -o $(TEST_BACKUP) $(TEST_BACKUP_OBJ) $(LIBRARIES)

$(TEST_RESTORE): $(TEST_RESTORE_OBJ) $(TOML) $(C_CLIENT_LIB) | $(DIR_TEST_BIN)
	$(CXX) $(TEST_LDFLAGS) -o $(TEST_RESTORE) $(TEST_RESTORE_OBJ) $(LIBRARIES)

-include $(TEST_DEPS)

# Requires the lcov tool to be installed
$(DIR_TEST_BIN)/aerospike-tools-backup.info: FORCE
	lcov -o $(DIR_TEST_BIN)/aerospike-tools-backup-test.info --capture --directory $(DIR_TEST_BIN)
	lcov -o $(DIR_TEST_BIN)/aerospike-tools-backup-test.info --quiet --extract $(DIR_TEST_BIN)/aerospike-tools-backup-test.info '$(DIR_SRC)/*' '$(DIR_INC)/*'
	lcov -o $(DIR_TEST_BIN)/aerospike-tools-backup.info --quiet -a $(DIR_TEST_BIN)/aerospike-tools-backup-baseline.info -a $(DIR_TEST_BIN)/aerospike-tools-backup-test.info

.PHONY: coverage
coverage: | $(DIR_TEST_BIN)/aerospike-tools-backup.info
	@lcov --summary $(DIR_TEST_BIN)/aerospike-tools-backup.info

.PHONY: coverage-init
coverage-init: $(TEST_BINS)
	@lcov --zerocounters --directory $(DIR_TEST_BIN)
	@lcov -o $(DIR_TEST_BIN)/aerospike-tools-backup-baseline.info --directory $(DIR_TEST_BIN) --capture --initial
	@lcov -o $(DIR_TEST_BIN)/aerospike-tools-backup-baseline.info --quiet --extract $(DIR_TEST_BIN)/aerospike-tools-backup-baseline.info '$(DIR_SRC)/*' '$(DIR_INC)/*'

.PHONY: do-test
do-test: | coverage-init
	@$(MAKE) -C . unit

.PHONY: report
report: | $(DIR_TEST_BIN)/aerospike-tools-backup.info
	@lcov -l $(DIR_TEST_BIN)/aerospike-tools-backup.info

.PHONY: report-display
report-display: | $(DIR_TEST_BIN)/aerospike-tools-backup.info
	@echo
	@rm -rf $(DIR_TEST_BIN)/html
	@mkdir -p $(DIR_TEST_BIN)/html
	@genhtml --prefix $(DIR_TEST_BIN)/html --ignore-errors source $(DIR_TEST_BIN)/aerospike-tools-backup.info --legend --title "test lcov" --output-directory $(DIR_TEST_BIN)/html

