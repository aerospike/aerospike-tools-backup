#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

static int open_count = 0;

typedef FILE *(*real_fopen_t)(const char*, const char*);

FILE* real_fopen(const char* pathname, const char* mode) {
  return ((real_fopen_t)dlsym(RTLD_NEXT, "fopen64"))(pathname, mode);
}

static int is_backup_file(const char* pathname) {
  size_t len = strlen(pathname);
  return len > 4 && strcmp(pathname + len - 4, ".asb") == 0;
}

FILE* fopen64(const char * pathname, const char * mode) {
  if (!is_backup_file(pathname) || ++open_count != 2) {
    return real_fopen(pathname, mode);
  }

  return NULL;
}
