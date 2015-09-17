/*
 * Copyright 2015 Aerospike, Inc.
 *
 * Portions may be licensed to Aerospike, Inc. under one or more contributor
 * license agreements.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

static const uint64_t rand_mult = 1162261467;   ///< Multiplier for the randomizer, 3^19 (ensures
                                                ///  that it's relatively prime with 2 and thus
                                                ///  works with mod-64 math).
static bool rand_flag = false;                  ///< Enables randomization.
static char *device = 0;                        ///< The path of the device from which to read.
static uint64_t block_size = 0;                 ///< The block size to be used for reads.
static uint64_t limit = 0;                      ///< We only use the first @ref limit bytes of the
                                                ///  device.
static uint64_t size = 0;                       ///< The total number of bytes to read. If larger
                                                ///  than @ref limit, blocks are read multiple
                                                ///  times.

///
/// Displays usage information.
///
static void
usage()
{
	fprintf(stderr, "usage: speed [-r] device block-size limit size\n");
}

///
/// Gets the current value of the monotonic timer in ms.
///
/// @param ms  The current monotonic time.
///
/// @result    `true`, if successful.
///
static bool
get_time(uint64_t *ms)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) {
		return false;
	}

	*ms = (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
	return true;
}

///
/// Parses a string of digits with an optional suffix into a 64-bit integer.
///
/// @param string  The string of digits to be parsed.
/// @param size    The resulting 64-bit integer.
///
/// @result        `true`, if successful.
///
static bool
string_to_size(const char *string, uint64_t *size)
{
	*size = 0;

	while (string[0] != 0) {
		if (string[0] >= '0' && string[0] <= '9') {
			*size = *size * 10 + (size_t)(string[0] - '0');
		} else if ((string[0] == 'k' || string[0] == 'K') && string[1] == 0) {
			*size *= 1024;
		} else if ((string[0] == 'm' || string[0] == 'M') && string[1] == 0) {
			*size *= 1024 * 1024;
		} else if ((string[0] == 'g' || string[0] == 'G') && string[1] == 0) {
			*size *= 1024 * 1024 * 1024;
		} else {
			*size = 0;
			return false;
		}

		++string;
	}

	return true;
}

///
/// It all starts here.
///
int32_t
main(int32_t ac, char *av[])
{
	for (int32_t i = 1; i < ac; ++i) {
		if (av[i][0] == '-') {
			switch (av[i][1]) {
			case 'r':
				rand_flag = true;
				break;

			default:
				fprintf(stderr, "invalid option: %s\n", av[i]);
				usage();
				return 1;
			}
		} else if (device == 0) {
			device = av[i];
		} else if (block_size == 0) {
			if (!string_to_size(av[i], &block_size)) {
				fprintf(stderr, "invalid block size: %s\n", av[i]);
				usage();
				return 1;
			}
		} else if (limit == 0) {
			if (!string_to_size(av[i], &limit)) {
				fprintf(stderr, "invalid limit: %s\n", av[i]);
				usage();
				return 1;
			}
		} else if (size == 0) {
			if (!string_to_size(av[i], &size)) {
				fprintf(stderr, "invalid size: %s\n", av[i]);
				usage();
				return 1;
			}
		}
	}

	bool err = false;

	if (device == 0) {
		fprintf(stderr, "missing device\n");
		err = true;
	}

	if (block_size == 0) {
		fprintf(stderr, "missing block size\n");
		err = true;
	}

	if (limit == 0) {
		fprintf(stderr, "missing limit\n");
		err = true;
	}

	if (size == 0) {
		fprintf(stderr, "missing size\n");
		err = true;
	}

	if (block_size != 0 && limit % block_size != 0) {
		fprintf(stderr, "limit must be a multiple of block size\n");
		err = true;
	}

	if (block_size != 0 && size % block_size != 0) {
		fprintf(stderr, "size must be a multiple of block size\n");
		err = true;
	}

	if (block_size != 0 && limit / block_size % 3 == 0) {
		fprintf(stderr, "limit must be relatively prime with random "
				"multiplier %lu\n", rand_mult);
		err = true;
	}

	if (err) {
		usage();
		return 1;
	}

	int32_t ret_val = 1;
	printf("reading %lu byte(s) from %s, block size = %lu, limit = %lu (%s)\n",
			size, device, block_size, limit, rand_flag ? "random" : "linear");
	uint8_t *buffer = malloc(block_size + 16384);

	if (buffer == 0) {
		fprintf(stderr, "cannot allocate block buffer\n");
		goto cleanup0;
	}

	uint64_t buff_off = (((uint64_t)buffer + 16383) & (uint64_t)~16383) - (uint64_t)buffer;
	printf("(buffer at %p, offset is %lu, effective buffer at %p)\n", buffer,
			buff_off, buffer + buff_off);
	int32_t fd = open(device, O_RDONLY | O_DIRECT);

	if (fd < 0) {
		fprintf(stderr, "cannot open device %s: %d, %s\n", device, errno,
				strerror(errno));
		goto cleanup1;
	}

	const uint64_t block_limit = limit / block_size;
	uint64_t count = 0;
	uint64_t start;

	if (!get_time(&start)) {
		fprintf(stderr, "cannot get start time\n");
		goto cleanup2;
	}

	uint64_t last_now = 0;

	while (count < size) {
		uint64_t block_count = count / block_size;

		if (rand_flag) {
			block_count = block_count * rand_mult;
		}

		block_count = block_count % block_limit;
		uint64_t seek = block_count * block_size;

		if (lseek(fd, (off_t)seek, SEEK_SET) < 0) {
			fprintf(stderr, "error while seeking to %lu: %d, %s\n", seek, errno,
					strerror(errno));
			goto cleanup2;
		}

		ssize_t res = read(fd, buffer + buff_off, block_size);

		if (res != (ssize_t)block_size) {
			fprintf(stderr, "error while reading at %lu: %ld byte(s) read\n", seek,
					res);

			if (res < 0) {
				fprintf(stderr, "error %d, %s\n", errno, strerror(errno));
			}

			goto cleanup2;
		}

		count += block_size;
		uint64_t now;

		if (!get_time(&now)) {
			fprintf(stderr, "cannot get current time\n");
			goto cleanup2;
		}

		if (now - last_now >= 5000 || count == size) {
			uint32_t perc = (uint32_t)(count * 100 / size);
			printf("%d%% complete\n", perc);
			last_now = now;
		}
	}

	uint64_t end;

	if (!get_time(&end)) {
		fprintf(stderr, "cannot get end time\n");
		goto cleanup2;
	}

	float sec = (float)(end - start) / (float)1000.0;
	float speed = (float)size / sec / (float)1024.0 / (float)1024.0;
	float iops = (float)(size / block_size) / sec;
	printf("%.1f s, %.1f MiB/s, %.1f IOPS\n", sec, speed, iops);
	ret_val = 0;

cleanup2:
	close(fd);

cleanup1:
	free(buffer);

cleanup0:
	return ret_val;
}
