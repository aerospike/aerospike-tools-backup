#define _GNU_SOURCE

#include <stdio.h>
#include <strings.h>
#include <dlfcn.h>

static int close_count = 0;

typedef int (*real_fclose_t)(FILE *);

int real_fclose(FILE *file) {
  return ((real_fclose_t)dlsym(RTLD_NEXT, "fclose"))(file);
}

int fclose(FILE *file) {
    close_count++;
    if (close_count != 3) {
        return real_fclose(file);
    }

    return -1;
}