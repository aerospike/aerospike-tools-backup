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

ifndef CLIENTREPO
$(error Please set the CLIENTREPO environment variable)
endif

OS := $(shell uname -s)
ARCH := $(shell uname -m)
PLATFORM := $(OS)-$(ARCH)
VERSION := $(shell git describe 2>/dev/null; if [ $${?} != 0 ]; then echo 'unknown'; fi)
ROOT = $(CURDIR)

CC := cc

DWARF := $(shell $(CC) -Wall -Wextra -O2 -o /tmp/asflags_$${$$} src/flags.c; \
		/tmp/asflags_$${$$}; rm /tmp/asflags_$${$$})
CFLAGS := -std=gnu99 $(DWARF) -O2 -march=nocona -fno-common -fno-strict-aliasing \
		-Wall -Wextra -Wconversion -Wsign-conversion -Wmissing-declarations \
		-Wno-implicit-fallthrough -Wno-unused-result \
		-D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=2 -DMARCH_$(ARCH) \
		-DTOOL_VERSION=\"$(VERSION)\"

LD := $(CC)
LDFLAGS := $(CFLAGS)

ifeq ($(OS), Linux)
LDFLAGS += -pthread
endif

TEST_CFLAGS := -std=gnu99 $(DWARF) -g -O2 -march=nocona -fno-common -fno-strict-aliasing \
		-Wall -Wextra -Wconversion -Wsign-conversion -Wmissing-declarations \
		-Wno-implicit-fallthrough -Wno-unused-result \
		-D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=2 -DMARCH_$(ARCH) \
		-DTOOL_VERSION=\"$(VERSION)\"
TEST_LDFLAGS := $(LDFLAGS) -fprofile-arcs -coverage -lcheck

DIR_INC := include
DIR_SRC := src
DIR_OBJ := obj
DIR_TEST := test/unit
DIR_TEST_BIN := test_target
DIR_TEST_OBJ := $(DIR_TEST_BIN)/obj
DIR_BIN := bin
DIR_LIB := lib
DIR_DOCS := docs
DIR_ENV := env
DIR_TOML := src/toml

INCLUDES := -I$(DIR_INC)
INCLUDES += -I$(DIR_TOML)
INCLUDES += -I$(CLIENTREPO)/src/include
INCLUDES += -I$(CLIENTREPO)/modules/common/src/include
INCLUDES += -I/usr/local/opt/openssl/include

LIBRARIES := $(CLIENTREPO)/target/$(PLATFORM)/lib/libaerospike.a
LIBRARIES += -L/usr/local/lib
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
LIBRARIES += -lz

ifeq ($(ZSTD_STATIC_PATH),)
  LIBRARIES += -lzstd
else
  LIBRARIES += $(ZSTD_STATIC_PATH)/libzstd.a
endif


ifeq ($(OS), Linux)
LIBRARIES += -ldl -lrt
LIBRARIES += -L$(DIR_TOML) -Wl,-l,:libtoml.a
else
LIBRARIES += $(DIR_TOML)/libtoml.a
endif

src_to_obj = $(1:$(DIR_SRC)/%.c=$(DIR_OBJ)/%.o)
obj_to_dep = $(1:%.o=%.d)
src_to_lib =

BACKUP_SRC_MAIN := $(DIR_SRC)/backup_main.c
RESTORE_SRC_MAIN := $(DIR_SRC)/restore_main.c
FLAGS_SRC_MAIN := $(DIR_SRC)/flags.c
TOML_SRC_MAIN := $(DIR_SRC)/toml/toml.c
HELPER_SRCS := $(filter-out $(BACKUP_SRC_MAIN) $(RESTORE_SRC_MAIN) \
	$(FLAGS_SRC_MAIN) $(TOML_SRC_MAIN),\
	$(shell find $(DIR_SRC) -name '*.c' -type f))

BACKUP_SRC := $(BACKUP_SRC_MAIN) $(HELPER_SRCS)
BACKUP_INC := $(patsubst $(DIR_SRC)%.c,%(DIR_OBJ)%.o,%(BACKUP_SRC))
BACKUP_OBJ := $(call src_to_obj, $(BACKUP_SRC))
BACKUP_DEP := $(call obj_to_dep, $(BACKUP_OBJ))

RESTORE_SRC := $(RESTORE_SRC_MAIN) $(HELPER_SRCS)
RESTORE_INC := $(patsubts $(DIR_SRC)/%.c,%(DIR_OBJ)/%.o,%(RESTORE_SRC))
RESTORE_OBJ := $(call src_to_obj, $(RESTORE_SRC))
RESTORE_DEP := $(call obj_to_dep, $(RESTORE_OBJ))

BACKUP := $(DIR_BIN)/asbackup
RESTORE := $(DIR_BIN)/asrestore
TOML := $(DIR_TOML)/libtoml.a

INCS := $(BACKUP_INC) $(RESTORE_INC)
SRCS := $(BACKUP_SRC) $(RESTORE_SRC)
OBJS := $(BACKUP_OBJ) $(RESTORE_OBJ)
DEPS := $(BACKUP_DEP) $(RESTORE_DEP)
BINS := $(TOML) $(BACKUP) $(RESTORE)

# sort removes duplicates
INCS := $(sort $(INCS))
SRCS := $(sort $(SRCS))
OBJS := $(sort $(OBJS))
DEPS := $(sort $(DEPS))


# test target
HELPER_OBJS := $(patsubst $(DIR_SRC)/%.c,$(DIR_TEST_OBJ)/src/%.o,$(HELPER_SRCS))
TEST_INC := $(INCS)
TEST_SRC := $(shell find $(DIR_TEST) -name '*.c' -type f)
TEST_OBJ := $(HELPER_OBJS) $(patsubst $(DIR_TEST)/%.c,$(DIR_TEST_OBJ)/unit/%.o,$(TEST_SRC))
TEST_DEP := $(patsubst $(DIR_TEST_OBJ)/%.o,$(DIR_TEST_OBJ)/%.d,$(TEST_OBJ))

.PHONY: all
all: $(BINS)

.PHONY: clean
clean:
	$(MAKE) -C $(DIR_TOML) clean
	rm -f $(DEPS) $(OBJS) $(BINS) $(TEST_OBJ) $(TEST_DEP)
	if [ -d $(DIR_OBJ) ]; then rmdir $(DIR_OBJ); fi
	if [ -d $(DIR_BIN) ]; then rmdir $(DIR_BIN); fi
	if [ -d $(DIR_TEST_OBJ) ]; then rm -r $(DIR_TEST_OBJ); fi
	if [ -d $(DIR_TEST_BIN) ]; then rm -r $(DIR_TEST_BIN); fi
	if [ -d $(DIR_DOCS) ]; then rm -r $(DIR_DOCS); fi
	if [ -d $(DIR_ENV) ]; then rm -rf $(DIR_ENV); fi

.PHONY: info
info:
	@echo
	@echo "  NAME:       " $(NAME)
	@echo "  OS:         " $(OS)
	@echo "  ARCH:       " $(ARCH)
	@echo "  CLIENTREPO: " $(CLIENT_PATH)
	@echo "  WD:         " $(shell pwd)
	@echo
	@echo "  PATHS:"
	@echo "      source:     " $(SOURCE)
	@echo "      target:     " $(TARGET_BASE)
	@echo "      includes:   " $(INC_PATH)
	@echo "      libraries:  " $(LIB_PATH)
	@echo
	@echo "  COMPILER:"
	@echo "      command:    " $(CC)
	@echo "      flags:      " $(CFLAGS)
	@echo
	@echo "  LINKER:"
	@echo "      command:    " $(LD)
	@echo "      flags:      " $(LDFLAGS)
	@echo

$(DIR_DOCS): $(INCS) $(SRCS) README.md
	if [ ! -d $(DIR_DOCS) ]; then mkdir $(DIR_DOCS); fi
	doxygen doxyfile

$(DIR_OBJ):
	mkdir $(DIR_OBJ)

$(DIR_BIN):
	mkdir $(DIR_BIN)

$(DIR_OBJ)/%.o: $(DIR_SRC)/%.c | $(DIR_OBJ)
	$(CC) $(CFLAGS) -MMD -o $@ -c $(INCLUDES) $<

$(BACKUP): $(BACKUP_OBJ) | $(DIR_BIN)
	echo $(HELPER_SRCS)
	$(CC) $(LDFLAGS) -o $(BACKUP) $(BACKUP_OBJ) $(LIBRARIES)

$(RESTORE): $(RESTORE_OBJ) | $(DIR_BIN)
	$(CC) $(LDFLAGS) -o $(RESTORE) $(RESTORE_OBJ) $(LIBRARIES)

$(TOML):
	$(MAKE) -C $(DIR_TOML)

-include $(BACKUP_DEP)
-include $(RESTORE_DEP)

.PHONY: test
test: unit integration

.PHONY: unit
unit: $(DIR_TEST_BIN)/test
	@$<

.PHONY: integration
integration: $(BINS)
	@./tests.sh $(DIR_ENV)

$(DIR_TEST_BIN):
	mkdir $@

$(DIR_TEST_OBJ): | $(DIR_TEST_BIN)
	mkdir $@

$(DIR_TEST_OBJ)/unit: | $(DIR_TEST_OBJ)
	mkdir $@

$(DIR_TEST_OBJ)/src: | $(DIR_TEST_OBJ)
	mkdir $@

$(DIR_TEST_OBJ)/unit/%.o: test/unit/%.c | $(DIR_TEST_OBJ)/unit
	$(CC) $(TEST_CFLAGS) $(INCLUDES) -o $@ -c $<

$(DIR_TEST_OBJ)/src/%.o: src/%.c | $(DIR_TEST_OBJ)/src
	$(CC) $(TEST_CFLAGS) $(INCLUDES) -fprofile-arcs -ftest-coverage -coverage -o $@ -c $<

$(DIR_TEST_BIN)/test: $(TEST_OBJ) $(CLIENTREPO)/target/$(PLATFORM)/lib/libaerospike.a $(TOML) | $(DIR_TEST_BIN)
	$(CC) -o $@ $(TEST_OBJ) $(CLIENTREPO)/target/$(PLATFORM)/lib/libaerospike.a $(TEST_LDFLAGS) $(LIBRARIES)

-include $(TEST_DEP)

# Summary requires the lcov tool to be installed
.PHONY: coverage
coverage: coverage-init do-test
	@echo
	@lcov --no-external --capture --initial --directory $(DIR_TEST_BIN) --output-file $(DIR_TEST_BIN)/aerospike-tools-backup.info
	@lcov --directory $(DIR_TEST_BIN) --capture --quiet --output-file $(DIR_TEST_BIN)/aerospike-tools-backup.info
	@lcov --summary $(DIR_TEST_BIN)/aerospike-tools-backup.info

.PHONY: coverage-init
coverage-init:
	@lcov --zerocounters --directory $(DIR_TEST_BIN)

.PHONY: do-test
do-test: | coverage-init
	@$(MAKE) -C . unit

.PHONY: report
report: coverage
	@lcov -l $(DIR_TEST_BIN)/aerospike-tools-backup.info

.PHONY: report-display
report-display: | $(DIR_TEST_BIN)/aerospike-tools-backup.info
	@echo
	@rm -rf $(DIR_TEST_BIN)/html
	@mkdir -p $(DIR_TEST_BIN)/html
	@genhtml --prefix $(DIR_TEST_BIN)/html --ignore-errors source $(DIR_TEST_BIN)/aerospike-tools-backup.info --legend --title "test lcov" --output-directory $(DIR_TEST_BIN)/html
	@xdg-open file://$(ROOT)/$(DIR_TEST_BIN)/html/index.html

