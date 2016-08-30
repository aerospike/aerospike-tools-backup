#
# Aerospike Backup/Restore
#
# Copyright (c) 2008-2016 Aerospike, Inc. All rights reserved.
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

CC := cc

DWARF := $(shell $(CC) -Wall -Wextra -O2 -o /tmp/asflags_$${$$} src/flags.c; \
		/tmp/asflags_$${$$}; rm /tmp/asflags_$${$$})
CFLAGS := -std=gnu99 $(DWARF) -O2 -march=nocona -fno-common -fno-strict-aliasing \
		-Wall -Wextra -Wconversion -Wsign-conversion -Wmissing-declarations \
		-D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=2 -DMARCH_$(ARCH)

ifeq ($(OS), Linux)
CFLAGS += -pthread -fstack-protector -Wa,--noexecstack
endif

LD := $(CC)
LDFLAGS := $(CFLAGS)

DIR_INC := include
DIR_SRC := src
DIR_OBJ := obj
DIR_BIN := bin
DIR_DOCS := docs
DIR_ENV := env

INCLUDES := -I$(DIR_INC)
INCLUDES += -I$(CLIENTREPO)/src/include
INCLUDES += -I$(CLIENTREPO)/modules/common/src/include

ifeq ($(OS), Darwin)
ifneq ($(wildcard /usr/local/opt/openssl/include),)
INCLUDES += -I/usr/local/opt/openssl/include
endif
endif

LIBRARIES := $(CLIENTREPO)/target/$(PLATFORM)/lib/libaerospike.a
LIBRARIES += -L/usr/local/lib
LIBRARIES += -lssl
LIBRARIES += -lcrypto
LIBRARIES += -lpthread
LIBRARIES += -lm
LIBRARIES += -lz

ifeq ($(OS), Linux)
LIBRARIES += -ldl -lrt
endif

src_to_obj = $(1:$(DIR_SRC)/%.c=$(DIR_OBJ)/%.o)
obj_to_dep = $(1:%.o=%.d)

BACKUP_INC := $(DIR_INC)/backup.h $(DIR_INC)/enc_text.h $(DIR_INC)/shared.h $(DIR_INC)/utils.h
BACKUP_SRC := $(DIR_SRC)/backup.c $(DIR_SRC)/utils.c $(DIR_SRC)/enc_text.c
BACKUP_OBJ := $(call src_to_obj, $(BACKUP_SRC))
BACKUP_DEP := $(call obj_to_dep, $(BACKUP_OBJ))

RESTORE_INC := $(DIR_INC)/restore.h $(DIR_INC)/dec_text.h $(DIR_INC)/serial.h $(DIR_INC)/shared.h \
		$(DIR_INC)/utils.h
RESTORE_SRC := $(DIR_SRC)/restore.c $(DIR_SRC)/utils.c $(DIR_SRC)/dec_text.c $(DIR_SRC)/serial.c
RESTORE_OBJ := $(call src_to_obj, $(RESTORE_SRC)) $(DIR_OBJ)/serial_dec.o
RESTORE_DEP := $(call obj_to_dep, $(RESTORE_OBJ))

FILL_INC := $(DIR_INC)/spec.h
FILL_SRC := $(DIR_SRC)/fill.c $(DIR_SRC)/spec.c
FILL_OBJ := $(call src_to_obj, $(FILL_SRC))
FILL_DEP := $(call obj_to_dep, $(FILL_OBJ))

BACKUP := $(DIR_BIN)/asbackup
RESTORE := $(DIR_BIN)/asrestore
FILL := $(DIR_BIN)/fill

INCS := $(BACKUP_INC) $(RESTORE_INC) $(FILL_INC)
SRCS := $(BACKUP_SRC) $(RESTORE_SRC) $(FILL_SRC)
OBJS := $(BACKUP_OBJ) $(RESTORE_OBJ) $(FILL_OBJ)
DEPS := $(BACKUP_DEP) $(RESTORE_DEP) $(FILL_DEP)
BINS := $(BACKUP) $(RESTORE) $(FILL)

ifeq ($(OS), Linux)
SPEED_INC :=
SPEED_SRC := $(DIR_SRC)/speed.c
SPEED_OBJ := $(call src_to_obj, $(SPEED_SRC))
SPEED_DEP := $(call obj_to_dep, $(SPEED_OBJ))

SPEED := $(DIR_BIN)/speed

INCS += $(SPEED_INC)
SRCS += $(SPEED_SRC)
OBJS += $(SPEED_OBJ)
DEPS += $(SPEED_DEP)
BINS += $(SPEED)
endif

# sort removes duplicates
INCS := $(sort $(INCS))
SRCS := $(sort $(SRCS))
OBJS := $(sort $(OBJS))
DEPS := $(sort $(DEPS))

.PHONY: all clean ragel

all: $(BINS)

clean:
	rm -f $(DEPS) $(OBJS) $(BINS)
	if [ -d $(DIR_OBJ) ]; then rmdir $(DIR_OBJ); fi
	if [ -d $(DIR_BIN) ]; then rmdir $(DIR_BIN); fi
	if [ -d $(DIR_DOCS) ]; then rm -r $(DIR_DOCS); fi
	if [ -d $(DIR_ENV) ]; then rm -r $(DIR_ENV); fi

tests:
	./tests.sh $(DIR_ENV)

ragel:
	ragel $(DIR_SRC)/spec.rl

$(DIR_DOCS): $(INCS) $(SRCS) README.md
	if [ ! -d $(DIR_DOCS) ]; then mkdir $(DIR_DOCS); fi
	doxygen doxyfile

$(DIR_OBJ):
	mkdir $(DIR_OBJ)

$(DIR_BIN):
	mkdir $(DIR_BIN)

$(DIR_OBJ)/%.o: $(DIR_SRC)/%.c | $(DIR_OBJ)
	$(CC) $(CFLAGS) -MMD -o $@ -c $(INCLUDES) $<

$(DIR_OBJ)/serial_dec.o: $(DIR_SRC)/serial.c | $(DIR_OBJ)
	$(CC) $(CFLAGS) -DDECODE_BASE64 -MMD -o $@ -c $(INCLUDES) $<

$(BACKUP): $(BACKUP_OBJ) | $(DIR_BIN)
	$(CC) $(LDFLAGS) -o $(BACKUP) $(BACKUP_OBJ) $(LIBRARIES)

$(RESTORE): $(RESTORE_OBJ) | $(DIR_BIN)
	$(CC) $(LDFLAGS) -o $(RESTORE) $(RESTORE_OBJ) $(LIBRARIES)

$(FILL): $(FILL_OBJ) | $(DIR_BIN)
	$(CC) $(LDFLAGS) -o $(FILL) $(FILL_OBJ) $(LIBRARIES)

-include $(BACKUP_DEP)
-include $(RESTORE_DEP)
-include $(FILL_DEP)

ifeq ($(OS), Linux)
$(SPEED): $(SPEED_OBJ) | $(DIR_BIN)
	$(CC) $(LDFLAGS) -o $(SPEED) $(SPEED_OBJ) $(LIBRARIES)

-include $(SPEED_DEP)
endif

