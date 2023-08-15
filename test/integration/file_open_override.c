#define _GNU_SOURCE

#include <stdio.h>
#include <strings.h>
#include <dlfcn.h>

static int open_count = 0;

typedef FILE *(*real_fopen_t)(const char*, const char*);

FILE* real_fopen(const char* pathname, const char* mode) {
  return ((real_fopen_t)dlsym(RTLD_NEXT, "fopen64"))(pathname, mode);
}

FILE* fopen64(const char * pathname, const char * mode) {
  open_count++;
  if (open_count != 5) {
    return real_fopen(pathname, mode);
  }

  return NULL;
}