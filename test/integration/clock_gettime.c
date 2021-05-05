#include <dlfcn.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// #define DEBUG

static int (*orig)(clockid_t clk_id, struct timespec *tp) = NULL;

int clock_gettime(clockid_t clk_id, struct timespec *tp)
{
	if (orig == NULL) {
		orig = dlsym(RTLD_NEXT, "clock_gettime");

		if (orig == NULL) {
			fprintf(stderr, "interceptor: dlsym() failed: %d (%s)\n", errno, strerror(errno));
			abort();
		}

		printf("interceptor: original function at %p\n", orig);
	}

	if (clk_id == CLOCK_REALTIME) {
		unsigned int fake_time;
		FILE *fh = fopen("work/clock_gettime.txt", "r");

		if (fh != NULL) {
			if (fscanf(fh, "%u\n", &fake_time) != 1) {
				fake_time = 0;
			}

			fclose(fh);
		} else {
			fake_time = 0;
		}

		if (fake_time > 0) {
#if defined DEBUG
			printf("interceptor: returning fake time %u\n", fake_time);
#endif
			tp->tv_sec = fake_time;
			tp->tv_nsec = 0;
			return 0;
		}
	}

	return orig(clk_id, tp);
}
