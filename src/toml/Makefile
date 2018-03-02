CC = gcc 
CFILES = toml.c

CFLAGS = -std=c99 -Wall -Wextra 
CFLAGS += -O2 -DNDEBUG
#CFLAGS += -O0 -g

LIB = libtoml.a

all: $(LIB)

libtoml.a: toml.o
	ar -rcs $@ $^

prefix ?= /usr/local

clean:
	rm -f *.o $(LIB)
