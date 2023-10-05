/*
 * Copyright 2015-2022 Aerospike, Inc.
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

//==========================================================
// Includes.
//

#include <float.h>
#include <math.h>
#include <stdatomic.h>

#include <utils.h>


//==========================================================
// Typedefs & constants.
//

#if defined __APPLE__
// Mutex initializer on OS X.
#define MUTEX_INIT PTHREAD_RECURSIVE_MUTEX_INITIALIZER
#else
// Mutex initializer on Linux.
#define MUTEX_INIT PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP
#endif

// Enables verbose logging.
atomic_bool g_verbose;
// Disables all logging output except for errors.
atomic_bool g_silent;

// Lookup table for base-64 decoding. Invalid characters yield 0xff. '=' (0x3d) yields 0x00 to
// make it a legal character.
const uint8_t b64map[256] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3e, 0xff, 0xff, 0xff, 0x3f,
	0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0xff, 0xff, 0xff, 0x00, 0xff, 0xff,
	0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
	0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
	0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};


//==========================================================
// Forward Declarations.
//

static pid_t thread_id(void);


//==========================================================
// Public API.
//

/*
 * Central log function. Writes a single log message.
 *
 * @param tag     The severity tag.
 * @param prefix  A prefix to be prepended to the log message.
 * @param format  The format string for the log message.
 * @param args    The arguments for the log message, according to the format string.
 * @param error   Indicates that errno information is to be added to the log message.
 */
void
log_line(const char *tag, const char *prefix, const char *format, va_list args, bool error)
{
	char buffer[10000];
	time_t now;
	struct tm now_tm;

	if ((now = time(NULL)) == (time_t)-1) {
		fprintf(stderr, "Error while getting current time, error %d, %s\n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (gmtime_r(&now, &now_tm) == NULL) {
		fprintf(stderr, "Error while calculating GMT, error %d, %s\n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	size_t index = 0;
	size_t length = strftime(buffer + index, sizeof(buffer) - 1, "%Y-%m-%d %H:%M:%S %Z ", &now_tm);

	if (length == 0) {
		fprintf(stderr, "Error while converting time to string, error %d, %s\n", errno,
				strerror(errno));
		exit(EXIT_FAILURE);
	}

	index += length;
	length = (size_t) snprintf(buffer + index, sizeof(buffer) - index - 1,
			"[%s] [%5d] %s", tag,
			(int32_t) (thread_id() % 100000), prefix);
	index += length;

	length = (size_t) vsnprintf(buffer + index, sizeof(buffer) - index - 1,
			format, args);
	index += length;

	if (index >= sizeof(buffer) - 1) {
		fprintf(stderr, "Buffer overflow while creating log message\n");
		exit(EXIT_FAILURE);
	}

	if (error) {
		length = (size_t)snprintf(buffer + index, sizeof(buffer) - index - 1,
				" (error %d: %s)",
				errno, strerror(errno));
		index += length;

		if (index >= sizeof(buffer) - 1) {
			fprintf(stderr, "Buffer overflow while creating log message\n");
			exit(EXIT_FAILURE);
		}
	}

	buffer[index] = '\n';
	fwrite(buffer, 1, index + 1, stderr);
}

/*
 * Logs a debug message.
 *
 * @param format  The format string for the debug message.
 */
void
_ver_fn(const char *format, ...)
{
	va_list args;

	if (!g_silent) {
		va_start(args, format);
		log_line("VER", "", format, args, false);
		va_end(args);
	}
}

/*
 * Logs an informational message.
 *
 * @param format  The format string for the informational message.
 */
void
inf(const char *format, ...)
{
	va_list args;

	if (!g_silent) {
		va_start(args, format);
		log_line("INF", "", format, args, false);
		va_end(args);
	}
}

/*
 * Logs an error message.
 *
 * @param format  The format string for the error message.
 */
void
err(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	log_line("ERR", "", format, args, false);
	va_end(args);
}

/*
 * Logs an error message and includes errno information.
 *
 * @param format  The format string for the error message.
 */
void
err_code(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	log_line("ERR", "", format, args, true);
	va_end(args);
}

/*
 * returns a string representation of the boolean value
 */
const char*
boolstr(bool val)
{
	static const char* str_vals[] = {
		"false",
		"true"
	};
	return str_vals[val != 0];
}

/*
 * Hex dump helper function. Feeds a hex dump of the given data to the given
 * function line by line.
 *
 * @param data    The data to be dumped.
 * @param len     The length of the data to be dumped.
 * @param output  The output function to be invoked for every line of the hex dump.
 */
static void
hex_dump(const void *data, uint32_t len, void (*output)(const char *format, ...))
{
	uint32_t i, k;
	char line[4 + 16 * 3 + 1 + 16 + 1];

	for (i = 0; i < len; i += k) {
		sprintf(line, "%04x", i);

		for (k = 0; k < 16 && i + k < len; ++k) {
			uint8_t x = ((uint8_t *)data)[i + k];
			sprintf(line + 4 + k * 3, " %02x", x);
			line[4 + 16 * 3 + 1 + k] = (char)(x >= 32 && x <= 126 ? x : '.');
		}

		line[4 + 16 * 3 + 1 + k] = 0;

		while (k < 16) {
			strcpy(line + 4 + k * 3, "   ");
			++k;
		}

		line[4 + 16 * 3] = ' ';
		output("%s", line);
	}
}

/*
 * Logs a debug hex dump of the given data.
 *
 * @param data  The data to be dumped.
 * @param len   The length of the data to be dumped.
 */
void
hex_dump_ver(const void *data, uint32_t len)
{
	hex_dump(data, len, _ver_fn);
}

/*
 * Logs an informational hex dump of the given data.
 *
 * @param data  The data to be dumped.
 * @param len   The length of the data to be dumped.
 */
void
hex_dump_inf(const void *data, uint32_t len)
{
	hex_dump(data, len, inf);
}

/*
 * Logs an error hex dump of the given data.
 *
 * @param data  The data to be dumped.
 * @param len   The length of the data to be dumped.
 */
void
hex_dump_err(const void *data, uint32_t len)
{
	hex_dump(data, len, err);
}

/*
 * Clones an as_vector of strings (char[N]) src into dst.
 */
bool
str_vector_clone(as_vector* dst, const as_vector* src)
{
	as_vector_init(dst, src->item_size, src->size);

	for (uint32_t i = 0; i < src->size; i++) {
		char* dst_loc = (char*) as_vector_reserve(dst);
		if (dst_loc == NULL) {
			return false;
		}

		memcpy(dst_loc, as_vector_get((as_vector*) src, i), src->item_size);
	}

	return true;
}

/*
 * Searches a vector of c strings and returns true if a match to str is found.
 */
bool
str_vector_contains(const as_vector* v, const char* str)
{
	for (uint32_t i = 0; i < v->size; i++) {
		const char* el = (const char*) as_vector_get((as_vector*) v, i);
		if (strcmp(el, str) == 0) {
			return true;
		}
	}
	return false;
}

/*
 * Returns a string representation of a vector of c strings stored in a static
 * buffer (i.e. this function is not thread-safe).
 */
char*
str_vector_tostring(const as_vector* v)
{
	static char buf[1024];
	uint64_t pos = 0;

	if (v->size == 0) {
		buf[0] = '\0';
	}

	for (uint32_t i = 0; i < v->size; i++) {
		pos += (uint64_t) snprintf(buf + pos, sizeof(buf) - pos, "%s",
				(const char*) as_vector_get((as_vector*) v, i));
		if (i < v->size - 1) {
			pos += (uint64_t) snprintf(buf + pos, sizeof(buf) - pos, ",");
		}
	}
	return buf;
}

/*
 * Log callback for the Aerospike client library. Receives log messages from the
 * Aerospike client and outputs them to our own log.
 *
 * @param level   The severity level of the log message.
 * @param func    The client library function that issued the log message.
 * @param file    The source code file that contains the function.
 * @param line    The source code line that issued the log message.
 * @param format  The format string of the log message.
 *
 * @result        Always `true`.
 */
static bool
log_callback(as_log_level level, const char *func, const char *file, uint32_t line,
		const char *format, ...)
{
	char prefix[1000];

	if ((size_t)snprintf(prefix, sizeof prefix, "[%s:%d][%s] ", file, line,
			func) >= sizeof prefix) {
		fprintf(stderr, "Buffer overflow while creating client log prefix");
		exit(EXIT_FAILURE);
	}

	char *tag = "???";

	switch (level) {
	case AS_LOG_LEVEL_ERROR:
	case AS_LOG_LEVEL_WARN:
		tag = "ERR";
		break;

	case AS_LOG_LEVEL_INFO:
		tag = "INF";

		if (g_silent) {
			return true;
		}
		break;

	case AS_LOG_LEVEL_DEBUG:
	case AS_LOG_LEVEL_TRACE:
		tag = "VER";

		if (g_silent) {
			return true;
		}
		break;
	}

	va_list args;
	va_start(args, format);
	log_line(tag, prefix, format, args, false);
	va_end(args);
	return true;
}

/*
 * Enables the Aerospike client log.
 */
void
enable_client_log(void)
{
	as_log_set_level(AS_LOG_LEVEL_INFO);
	as_log_set_callback(log_callback);
}

/*
 * A wrapper around `cf_malloc()` that exits on errors.
 */
void *
safe_malloc(size_t size)
{
	void *mem = cf_malloc(size);

	if (mem == NULL) {
		err_code("Error while allocating %zu byte(s)", size);
		exit(EXIT_FAILURE);
	}

	return mem;
}

/*
 * A wrapper around `cf_strdup()` that exits on errors. Will not attempt to
 * duplicate the string if it is NULL.
 */
char *
safe_strdup(const char *string)
{
	if (string == NULL) {
		return NULL;
	}

	char *res = cf_strdup(string);

	if (res == NULL) {
		err_code("Error while duplicating string %s", string);
		exit(EXIT_FAILURE);
	}

	return res;
}

/*
 * A wrapper around `pthread_mutex_lock()` that uses @ref mutex and that exits on errors.
 */
void
safe_lock(pthread_mutex_t* mutex)
{
	if (pthread_mutex_lock(mutex) != 0) {
		err_code("Error while locking mutex");
		exit(EXIT_FAILURE);
	}
}

/*
 * A wrapper around `pthread_mutex_unlock()` that uses @ref mutex and that exits on errors.
 */
void
safe_unlock(pthread_mutex_t* mutex)
{
	if (pthread_mutex_unlock(mutex) != 0) {
		err_code("Error while unlocking mutex");
		exit(EXIT_FAILURE);
	}
}

/*
 * Wait on a condition variable for at most one second.
 */
void
safe_wait(pthread_cond_t* cond, pthread_mutex_t* mutex)
{
#ifdef __APPLE__
	// MacOS uses gettimeofday instead of the monotonic clock for timed waits on
	// condition variables
	struct timespec t;
	struct timeval tv;
	gettimeofday(&tv, NULL);
	TIMEVAL_TO_TIMESPEC(&tv, &t);
#else
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
#endif /* __APPLE__ */

	// wait for one second
	t.tv_sec += 1;

	int res = pthread_cond_timedwait(cond, mutex, &t);
	if (res != 0 && res != ETIMEDOUT) {
		err_code("Error while waiting for condition");
		exit(EXIT_FAILURE);
	}
}

/*
 * A version of `pthread_cond_broadcast()` that exits on errors.
 */
void
safe_signal(pthread_cond_t *cond)
{
	if (pthread_cond_broadcast(cond) != 0) {
		err_code("Error while signaling condition");
		exit(EXIT_FAILURE);
	}
}

/*
 * Performs the inverse erf of y, i.e. gives x such that erf(x) == y.
 *
 * From: https://github.com/antelopeusersgroup/antelope_contrib/blob/master/lib/location/libgenloc/erfinv.c
 */
double
erfinv(double y)
{
#define CENTRAL_RANGE 0.7
	/* coefficients in rational expansion */
	const double a[4] = { 0.886226899, -1.645349621,  0.914624893, -0.140543331};
	const double b[4] = {-2.118377725,  1.442710462, -0.329097515,  0.012229801};
	const double c[4] = {-1.970840454, -1.624906493,  3.429567803,  1.641345311};
	const double d[2] = { 3.543889200,  1.637067800};
	double x;

	if (fabs(y) > 1.0) {
		return atof("NaN");
	}
	if (y == 1.0) {
		return DBL_MAX;
	}
	if (y == -1.0) {
		return -DBL_MAX;
	}

	if (fabs(y) <= CENTRAL_RANGE) {
		double z = y*y;
		double num = ((a[3]*z + a[2])*z + a[1])*z + a[0];
		double dem = (((b[3]*z + b[2])*z + b[1])*z + b[0])*z + 1.0;
		x = y * num / dem;
	}
	else {
		double z = sqrt(-log((1.0 - fabs(y)) / 2.0));
		double num = ((c[3]*z + c[2])*z + c[1])*z + c[0];
		double dem = (d[1]*z + d[0])*z + 1.0;
		x = copysign(1.0, y) * num / dem;
	}
	/* Two steps of Newton-Raphson correction */
	x = x - (erf(x) - y) / ((2.0 / sqrt(M_PI)) * exp(-x * x));
	x = x - (erf(x) - y) / ((2.0 / sqrt(M_PI)) * exp(-x * x));

	return x;
}

/*
 * Given the target probability (confidence) and number of samples taken from
 * an identical distribution, gives the z-score of the upper confidence interval
 * of the sum of <n_records> samples from that distribution.
 */
double
confidence_z(double p, uint64_t n_records)
{
	// a lower bound of 1 - (p ^ (1 / n_records))
	double q = (1 - p) / (double) n_records;
	// the z-score of the upper confidence interval
	double z = sqrt(2) * -erfinv(q * 2 - 1);
	return z;
}

/*
 * Allocates a buffer large enough to hold the given formatted string and
 * returns a pointer to the buffer with the format string written
 */
char*
dyn_sprintf(const char* format, ...)
{
	va_list args;
	va_start(args, format);
	size_t len = (size_t) vsnprintf(NULL, 0, format, args);
	va_end(args);

	char* buf = (char*) cf_malloc((len + 1) * sizeof(char));
	if (buf == NULL) {
		err("Unable to allocate %zu bytes for snprintf buffer string",
				len + 1);
		return NULL;
	}

	va_start(args, format);
	vsnprintf(buf, len + 1, format, args);
	va_end(args);

	return buf;
}

/*
 * Turns a string of digits into an unsigned 64-bit value.
 *
 * @param string  The string of digits.
 * @param val     The output integer.
 *
 * @result        `true`, if successful.
 */
bool
better_atoi(const char *string, int64_t *val)
{
	char *end;
	*val = strtol(string, &end, 10);
	return end != string && *end == '\0';
}

/*
 * Parses a "YYYY-MM-DD_HH:MM:SS" date and time string (local time) into nanoseconds
 * since the epoch (GMT).
 *
 * @param string  The date and time string.
 * @param nanos   The nanoseconds passed since the epoch.
 *
 * @result        `true`, if successful.
 */
bool
parse_date_time(const char *string, int64_t *nanos)
{
	ver("Parsing date and time string %s", string);

	time_t now = time(NULL);

	if (now == (time_t)-1) {
		err("Error while getting current time");
		return false;
	}

	struct tm local;

	if (localtime_r(&now, &local) == NULL) {
		err("Error while calculating local time");
		return false;
	}

	int32_t year;
	int32_t month;

	switch (strlen(string)) {
	case 10:
		// YYYY-MM-DD, missing time, assume 00:00:00
		if (sscanf(string, "%4d-%2d-%2d", &year, &month, &local.tm_mday) != 3 || year < 1900) {
			err("Date format error in %s", string);
			return false;
		}

		local.tm_year = year - 1900;
		local.tm_mon = month - 1;
		local.tm_hour = 0;
		local.tm_sec = 0;
		local.tm_min = 0;
		break;

	case 8:
		// HH:MM:SS, missing date, assume today's date
		if (sscanf(string, "%2d:%2d:%2d", &local.tm_hour, &local.tm_min, &local.tm_sec) != 3) {
			err("Time format error in %s", string);
			return false;
		}

		break;

	case 19:
		// YYYY-MM-DD_HH:MM:SS
		if (sscanf(string, "%4d-%2d-%2d_%2d:%2d:%2d",
				&year, &month, &local.tm_mday, &local.tm_hour, &local.tm_min,
				&local.tm_sec) != 6 || year < 1900) {
			err("Date/time format error in %s", string);
			return false;
		}

		local.tm_year = year - 1900;
		local.tm_mon = month - 1;
		break;

	default:
		return false;
	}

	time_t secs = mktime(&local);

	if (secs == (time_t)-1) {
		err("Error while calculating epoch time");
		return false;
	}

	*nanos = (int64_t)secs * 1000000000;
	return true;
}

bool
parse_host(char** pp, char** host, char** port)
{
	// Format: address1:port1
	// Destructive parse. String is modified.
	// IPV6 addresses can start with bracket.
	char* p = *pp;

	if (*p == '[') {
		*host = ++p;

		while (*p) {
			if (*p == ']') {
				*p++ = 0;

				if (*p == ':') {
					p++;
					*port = p;
					*pp = p;
					return true;
				}
				else {
					break;
				}
			}
			p++;
		}
	}
	else {
		*host = p;

		while (*p) {
			if (*p == ':') {
				*p++ = 0;
				*port = p;
				*pp = p;
				return true;
			}
			p++;
		}
	}
	*port = 0;
	return false;
}

/*
 * Converts the given nanoseconds since the epoch (GMT) into a "YYYY-MM-DD_HH:MM:SS"
 * date and time string (local time).
 *
 * @param nanos   The nanoseconds to be converted.
 * @param buffer  The output buffer to receive the converted result.
 * @param size    The size of the output buffer.
 *
 * @result        `true`, if successful.
 */
bool
format_date_time(int64_t nanos, char *buffer, size_t size)
{
	time_t gmt = (time_t)(nanos / 1000000000);
	struct tm local;

	if (localtime_r(&gmt, &local) == NULL) {
		err("Error while calculating local time");
		return false;
	}

	if (strftime(buffer, size, "%Y-%m-%d %H:%M:%S %Z", &local) == 0) {
		err("Error while formatting local time");
		return false;
	}

	return true;
}

/*
 * Get the current time using the clock used for timed waits in libpthread.
 */
void
get_current_time(struct timespec* now)
{
#ifdef __APPLE__
	// MacOS uses gettimeofday instead of the monotonic clock for timed waits on
	// mutexes/condition variables
	struct timeval tv;
	gettimeofday(&tv, NULL);
	TIMEVAL_TO_TIMESPEC(&tv, now);
#else
	clock_gettime(CLOCK_MONOTONIC, now);
#endif /* __APPLE__ */
}

/*
 * Adds "us" microseconds to the timespec "ts".
 *
 * "us" can't be too large (> (ULONG_MAX - 999999999) / 1000), otherwise integer
 * overflow will occur in the tv_nsec field. But this number is very large
 * (18446744072709551), amounting to about ~584 years, so assume this won't
 * happen.
 */
void
timespec_add_us(struct timespec* ts, uint64_t us)
{
	ts->tv_nsec += 1000 * us;
	ts->tv_sec += ts->tv_nsec / 1000000000;
	ts->tv_nsec = ts->tv_nsec % 1000000000;
}

/*
 * Returns the number of microseconds from timespec "from" until timespec
 * "until".
 */
uint64_t
timespec_diff(const struct timespec* from, const struct timespec* until)
{
	uint64_t n_secs = (uint64_t) (until->tv_sec - from->tv_sec);
	uint64_t n_nsecs = (uint64_t) (1000000000 + until->tv_nsec - from->tv_nsec);
	return (n_secs * 1000000) + (n_nsecs / 1000 - 1000000);
}

/*
 * returns true if the given timespec is in the future
 */
bool
timespec_has_not_happened(struct timespec* ts)
{
	struct timespec now;
	get_current_time(&now);

	return now.tv_sec < ts->tv_sec ||
		(now.tv_sec == ts->tv_sec && now.tv_nsec < ts->tv_nsec);
}

/*
 * '\'-escapes spaces and line feeds in a string. Used by the @ref escape() macro.
 *
 * @param source  The string to be escaped.
 * @param dest    The output buffer for the escaped string. May be `NULL` to determine the
 *                length of the escaped string.
 *
 * @result        An esc_res, i.e., an (output buffer, length) pair.
 */
esc_res
escape_space(const char *source, char *dest)
{
	size_t k = 0;

	for (size_t i = 0; source[i] != 0; ++i) {
		char ch = source[i];

		if (ch == '\\' || ch == ' ' || ch == '\n') {
			if (dest != NULL) {
				dest[k] = '\\';
			}

			++k;
		}

		if (dest != NULL) {
			dest[k] = ch;
		}

		++k;
	}

	if (dest != NULL) {
		dest[k] = 0;
	}

	return (esc_res){ dest, ++k };
}

/*
 * '\'-unescapes a string.
 *
 * @param source  The string to be unescaped.
 * @param dest    The output buffer for the unescaped string. May be `NULL` to determine the
 *                length of the unescaped string.
 *
 * @result        An esc_res, i.e., an (output buffer, length) pair.
 */
esc_res
unescape_space(const char *source, char *dest)
{
	size_t k = 0;
	bool esc = false;

	for (size_t i = 0; source[i] != 0; ++i) {
		char ch = source[i];

		if (ch == '\\' && !esc) {
			esc = true;
			continue;
		}

		esc = false;

		if (dest != NULL) {
			dest[k] = ch;
		}

		++k;
	}

	if (dest != NULL) {
		dest[k] = 0;
	}

	return (esc_res){ dest, ++k };
}

/*
 * Removes space characters at the beginning and end of a string.
 *
 * @param str  The string to be trimmed.
 *
 * @result     A pointer to the beginning of the trimmed string.
 */
char *
trim_string(char *str)
{
	size_t len = strlen(str);
	char *end = str + len - 1;

	while (end >= str && isspace(*end)) {
		--end;
	}

	*(end + 1) = 0;

	while (isspace(*str)) {
		++str;
	}

	return str;
}

/*
 * Splits a string at the given split character into a vector of strings. Optionally trims
 * the resulting parts.
 *
 * @param str    The string to be split.
 * @param split  The character to split at.
 * @param trim   Requests trimming of the resulting parts.
 * @param vec    The result vector to be populated.
 */
void
split_string(char *str, char split, bool trim, as_vector *vec)
{
	char *prev = str;
	bool stop = false;

	while (!stop) {
		stop = *str == 0;

		if (*str == split || stop) {
			*str = 0;
			char *append = trim ? trim_string(prev) : prev;
			as_vector_append(vec, &append);
			prev = str + 1;
		}

		++str;
	}
}

/*
 * Pretty-prints the given number of seconds.
 *
 * @param seconds  The number of seconds to be pretty-printed.
 * @param buffer   The output buffer to receive the formatted result.
 * @param size     The size of the output buffer.
 */
void
format_eta(int32_t seconds, char *buffer, size_t size)
{
	size_t length = 0;

	if (seconds > 100 * 86400) {
		length = (size_t)snprintf(buffer, size, "%s", ">100d");

		if (length >= size) {
			fprintf(stderr, "Buffer overflow while formatting days\n");
			exit(EXIT_FAILURE);
		}

		return;
	}

	if (seconds < 0) {
		seconds = 0;
	}

	int32_t divisors[] = { 86400, 3600, 60, 1 };
	char labels[] = { 'd', 'h', 'm', 's' };
	size_t index = 0;
	bool printed = false;

	for (uint32_t i = 0; i < 4; ++i) {
		int32_t val = seconds / divisors[i];

		if (val == 0 && !printed && i < 3) {
			continue;
		}

		seconds = seconds - val * divisors[i];
		length = (size_t)snprintf(buffer + index, size - index, "%d%c", val, labels[i]);
		index += length;

		if (index >= size) {
			fprintf(stderr, "Buffer overflow while formatting ETA\n");
			exit(EXIT_FAILURE);
		}

		printed = true;
	}
}

/*
 * Formats a character as a string. Unprintable characters use "\x..." notation.
 *
 * For thread safety, this function uses a fixed number of static buffers based on the maximal
 * number of threads.
 *
 * @param ch  The character to be formatted.
 *
 * @result    The string representing the character.
 */
char *
print_char(int32_t ch)
{
	// allow print_char() to be used up to 4 times in a single expression (e.g., function call)
	static char buff[MAX_THREADS * 4][5];
	static uint32_t index = 0;

	/*
	 * atomically perform the following operation:
	 *
	 * uint32_t i = index++;
	 * if (index >= MAX_THREADS * 4) {
	 *     index = 0;
	 * }
	 *
	 * use weak atomic compare exchange since this is very cheap, and relaxed
	 * memory ordering on both success and fail since there are no other
	 * synchronization requirements
	 */
	uint32_t i = __atomic_load_n(&index, __ATOMIC_RELAXED);
	while (!__atomic_compare_exchange_n(&index, &i, (i + 1) % (MAX_THREADS * 4),
				true, __ATOMIC_RELAXED, __ATOMIC_RELAXED));

	if (ch >= 32 && ch <= 126) {
		snprintf(buff[i], sizeof buff[i], "\"%c\"", ch);
	} else {
		snprintf(buff[i], sizeof buff[i], "\\x%02x", ch & 255);
	}

	return buff[i];
}

/*
 * writes an integer to a file in a consistent format (regardless of machine
 * endian-ness)
 */
bool
write_int64(uint64_t val, file_proxy_t* fd)
{
	uint64_t rval = htobe64(val);
	return file_proxy_write(fd, &rval, sizeof(rval)) == sizeof(rval);
}

/*
 * writes an integer to a file in a consistent format (regardless of machine
 * endian-ness)
 */
bool
write_int32(uint32_t val, file_proxy_t* fd)
{
	uint32_t rval = htobe32(val);
	return file_proxy_write(fd, &rval, sizeof(rval)) == sizeof(rval);
}

/*
 * reads an integer from a file written using write_int64
 */
bool
read_int64(uint64_t* val, file_proxy_t* fd)
{
	uint64_t rval;

	if (file_proxy_read(fd, &rval, sizeof(rval)) != sizeof(rval)) {
		return false;
	}

	*val = be64toh(rval);

	return true;
}

/*
 * reads an integer from a file written using write_int32
 */
bool
read_int32(uint32_t* val, file_proxy_t* fd)
{
	uint32_t rval;

	if (file_proxy_read(fd, &rval, sizeof(rval)) != sizeof(rval)) {
		return false;
	}

	*val = be32toh(rval);

	return true;
}

/*
 * Reads a character from a file descriptor. Updates the current line and column
 * number as well as
 * the total number of read bytes.
 *
 * @param fd       The file descriptor to read from.
 * @param line_no  The line number. `line_no[0]` is the current line, `line_no[1]`
 *                 is the next line.
 * @param col_no   The column number. `col_no[0]` is the current column,
 *                 `col_no[1]` is the next column.
 *
 * @result         The read character on success, otherwise `EOF`.
 */
int32_t
read_char(io_read_proxy_t *fd, uint32_t *line_no, uint32_t *col_no)
{
	line_no[0] = line_no[1];
	col_no[0] = col_no[1];

	int32_t ch = io_proxy_getc_unlocked(fd);

	switch (ch) {
		case EOF:
			if (io_proxy_error(fd) != 0) {
				err("Error while reading backup block (line %u, col %u)",
						line_no[0], col_no[0]);
				return EOF;
			}

			err("Unexpected end of file in backup block (line %u, col %u)",
					line_no[0], col_no[0]);
			return EOF;

		case '\n':
			++line_no[1];
			col_no[1] = 1;
			return ch;

		default:
			++col_no[1];
			return ch;
	}
}

/*
 * Reads from a file descriptor, decodes base-64 data, and returns the next
 * decoded byte. Updates the current line and column number as well as the total
 * number of read bytes.
 *
 * The function reads 4 bytes at a time, decodes them into 3 bytes, buffers 2 of
 * those 3 bytes, and returns the 1 remaining byte. Subsequent calls will read
 * the 2 buffered bytes. After that, everything starts over.
 *
 * @param fd       The file descriptor to read from.
 * @param line_no  The line number. `line_no[0]` is the current line,
 *                 `line_no[1]` is the next line.
 * @param col_no   The column number. `col_no[0]` is the current column,
 *                 `col_no[1]` is the next column.
 * @param bytes    Incremented, if a character was successfully read.
 * @param b64c     The base-64 context used, for example, to store buffered
 *                 bytes.
 *
 * @result         The decoded byte on success, otherwise `EOF`.
 */
int32_t
read_char_dec(io_read_proxy_t *fd, uint32_t *line_no, uint32_t *col_no,
		b64_context *b64c)
{
	if (LIKELY(b64c->index < 2)) {
		return b64c->buffer[b64c->index++];
	}

	int32_t ch1 = read_char(fd, line_no, col_no);
	int32_t ch2 = read_char(fd, line_no, col_no);
	int32_t ch3 = read_char(fd, line_no, col_no);
	int32_t ch4 = read_char(fd, line_no, col_no);

	if (UNLIKELY(ch1 == EOF || ch2 == EOF || ch3 == EOF || ch4 == EOF)) {
		err("Unexpected end of file in base-64 data");
		return EOF;
	}

	if (UNLIKELY(ch4 == '=')) {
		b64c->size += ch3 == '=' ? 1 : 2;
	} else {
		b64c->size += 3;
	}

	int32_t dig1 = b64map[ch1];
	int32_t dig2 = b64map[ch2];
	int32_t dig3 = b64map[ch3];
	int32_t dig4 = b64map[ch4];

	if (UNLIKELY(dig1 == 0xff || dig2 == 0xff || dig3 == 0xff || dig4 == 0xff)) {
		err("Invalid base-64 character (%s, %s, %s, or %s at or before line %u, col %u)",
				print_char(ch1), print_char(ch2), print_char(ch3), print_char(ch4),
				line_no[0], col_no[0]);
		return EOF;
	}

	b64c->buffer[0] = (uint8_t)((dig2 << 4) | (dig3 >> 2));
	b64c->buffer[1] = (uint8_t)((dig3 << 6) | dig4);
	b64c->index = 0;
	return (dig1 << 2) | (dig2 >> 4);
}

int
peek_char(io_read_proxy_t *fd, uint32_t *line_no, uint32_t *col_no)
{
	line_no[0] = line_no[1];
	col_no[0] = col_no[1];

	int32_t ch = io_proxy_peekc_unlocked(fd);

	switch (ch) {
	case EOF:
		if (io_proxy_error(fd) != 0) {
			err("Error while reading backup block (line %u, col %u)", line_no[0], col_no[0]);
			return EOF;
		}

		err("Unexpected end of file in backup block (line %u, col %u)", line_no[0], col_no[0]);
		return EOF;
	}
	return ch;
}

/*
 * Expects the given character to be the next character read from the given file descriptor.
 *
 * @param fd       The file descriptor.
 * @param line_no  The current line number.
 * @param col_no   The current column number.
 * @param ch       The expected character.
 *
 * @result         `true`, if successful.
 */
bool
expect_char(io_read_proxy_t *fd, uint32_t *line_no, uint32_t *col_no,
		int32_t ch)
{
	int32_t x = read_char(fd, line_no, col_no);

	if (UNLIKELY(x == EOF)) {
		return false;
	}

	if (UNLIKELY(x != ch)) {
		err("Unexpected character %s in backup block (line %u, col %u), expected %s", print_char(x),
				line_no[0], col_no[0], print_char(ch));
		return false;
	}

	return true;
}

/*
 * Reads the given number of bytes from the given file descriptor.
 *
 * @param fd       The file descriptor.
 * @param line_no  The current line number.
 * @param col_no   The current column number.
 * @param buffer   The output buffer for the read bytes.
 * @param size     The number of bytes to be read.
 *
 * @result         `true`, if successful.
 */
bool
read_block(io_read_proxy_t *fd, uint32_t *line_no, uint32_t *col_no,
		void *buffer, size_t size)
{
	for (size_t i = 0; i < size; ++i) {
		int32_t ch = read_char(fd, line_no, col_no);

		if (UNLIKELY(ch == EOF)) {
			return false;
		}

		((char *)buffer)[i] = (char)ch;
	}

	return true;
}

/*
 * Reads the given number of characters from the given file descriptor and
 * base-64 decodes them.
 *
 * @param fd       The file descriptor.
 * @param line_no  The current line number.
 * @param col_no   The current column number.
 * @param buffer   The output buffer for the decoded bytes.
 * @param size     The number of characters to be read. Note that this is not
 *                 the size of the output buffer. This is the number of base-64
 *                 characters. The output buffer, however, receives the decoded
 *                 bytes and thus is smaller.
 * @param b64c     The base-64 context to be used for decoding.
 *
 * @result         `true`, if successful.
 */
bool
read_block_dec(io_read_proxy_t *fd, uint32_t *line_no, uint32_t *col_no,
		void *buffer, size_t size, b64_context *b64c)
{
	for (size_t i = 0; i < size; ++i) {
		int32_t ch = read_char_dec(fd, line_no, col_no, b64c);

		if (UNLIKELY(ch == EOF)) {
			return false;
		}

		((char *)buffer)[i] = (char)ch;
	}

	return true;
}

/*
 * Obtains the node IDs of the cluster from the Aerospike client library.
 * Optionally only considers user-specified nodes.
 *
 * The first pass just counts the nodes, the second pass actually gets their IDs.
 *
 * @param clust         The Aerospike cluster.
 * @param node_specs    The IP addresses and ports of the user-specified nodes.
 * @param n_node_specs  The number of user-specified nodes. Zero means "give me
 *                      all cluster nodes."
 * @param node_names    The created array of node IDs.
 * @param n_node_names  The number of elements in the created array.
 */
void
get_node_names(as_cluster *clust, node_spec *node_specs, uint32_t n_node_specs,
		char (**node_names)[][AS_NODE_NAME_SIZE], uint32_t *n_node_names)
{
	as_nodes *nodes = as_nodes_reserve(clust);

	for (int32_t pass = 1; pass <= 2; ++pass) {
		*n_node_names = 0;

		for (uint32_t i = 0; i < nodes->size; ++i) {
			as_node *node = nodes->array[i];
			bool keep;

			if (n_node_specs == 0) {
				keep = true;
			} else {
				keep = false;
				as_address *addrs = node->addresses;

				for (uint32_t k = 0; !keep && k < node->address4_size; ++k) {
					as_address *addr = &addrs[k];
					struct sockaddr_in *v4 = (struct sockaddr_in *)&addr->addr;

					for (uint32_t m = 0; !keep && m < n_node_specs; ++m) {
						if (node_specs[m].family != AF_INET) {
							continue;
						}

						keep = v4->sin_addr.s_addr == node_specs[m].ver.v4.s_addr &&
								v4->sin_port == node_specs[m].port;

						if (keep && pass == 2 && g_verbose) {
							ver("Found node for %s:%d", node_specs[m].addr_string,
									ntohs(node_specs[m].port));
						}
					}
				}

				for (uint32_t k = 0; !keep && k < node->address6_size; ++k) {
					as_address *addr = &addrs[AS_ADDRESS4_MAX + k];
					struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&addr->addr;

					for (uint32_t m = 0; !keep && m < n_node_specs; ++m) {
						if (node_specs[m].family != AF_INET6) {
							continue;
						}

						keep = memcmp(&v6->sin6_addr, &node_specs[m].ver.v6, 16) == 0 &&
								v6->sin6_port == node_specs[m].port;

						if (keep && pass == 2 && g_verbose) {
							ver("Found node for %s:%d", node_specs[m].addr_string,
									ntohs(node_specs[m].port));
						}
					}
				}
			}

			if (keep) {
				if (pass == 2) {
					ver("Adding node %s", node->name);

					memcpy((**node_names)[*n_node_names], node->name, AS_NODE_NAME_SIZE);
				}

				++(*n_node_names);
			}
		}

		if (pass == 1) {
			*node_names = safe_malloc(*n_node_names * AS_NODE_NAME_SIZE);
		}
	}

	as_nodes_release(nodes);
}

/*
 * Retrieves the given info value from the given node, parses it, and feeds the resulting
 * info key-value pairs to the given callback function.
 *
 * @param as         The Aerospike client instance.
 * @param value      The info value to be retrieved.
 * @param node_name  The name of the node to be queried.
 * @param context    The opaque user-specified context for the callback.
 * @param callback   The callback to be invoked for each key-value pair.
 * @param kv_split   Indicates an info response of the form "<k1>=<v1>[;<k2>=<v2>[;...]]".
 *
 * @result          `true`, if successful.
 */
bool
get_info(aerospike *as, const char *value, const char *node_name, void *context,
		info_callback callback, bool kv_split)
{
	bool res = false;

	ver("Getting info value %s for node %s", value, node_name);

	as_node *node = as_node_get_by_name(as->cluster, node_name);

	if (node == NULL) {
		err("Node %s disappeared from the cluster", node_name);
		goto cleanup0;
	}

	as_policy_info policy;
	as_policy_info_init(&policy);
	policy.timeout = TIMEOUT;

	char *resp = NULL;
	as_error ae;

	if (aerospike_info_node(as, &ae, &policy, node, value, &resp) != AEROSPIKE_OK) {
		as_node_release(node);
		err("Error while retrieving info from node %s - code %d: %s at %s:%d", node_name, ae.code,
			ae.message, ae.file, ae.line);
		goto cleanup0;
	}

	as_node_release(node);

	ver("Parsing info");

	char *info = NULL;

	if (as_info_parse_single_response(resp, &info) != AEROSPIKE_OK) {
		err("Error while parsing single info response");
		goto cleanup1;
	}

	if (info[0] == 0) {
		// Empty result is a valid result
		return true;
	}

	char *clone = safe_strdup(info);
	as_vector info_vec;
	as_vector_inita(&info_vec, sizeof (void *), 25);

	split_string(info, ';', false, &info_vec);

	for (uint32_t i = 0; i < info_vec.size; ++i) {
		char *key;
		char *value;

		if (kv_split) {
			key = as_vector_get_ptr(&info_vec, i);
			char *equals = strchr(key, '=');

			if (equals == NULL) {
				err("Invalid info string %s (missing \"=\")", clone);
				goto cleanup2;
			}

			*equals = 0;
			value = equals + 1;
		} else {
			key = NULL;
			value = as_vector_get_ptr(&info_vec, i);
		}

		if (!callback(context, key, value)) {
			err("Info callback reports an error");
			goto cleanup2;
		}
	}

	res = true;

cleanup2:
	as_vector_destroy(&info_vec);
	cf_free(clone);

cleanup1:
	cf_free(resp);

cleanup0:
	return res;
}

/*
 * Parses the given secondary index information string obtained from a cluster.
 *
 * @param ns         The namespace that contains the secondary index.
 * @param index_str  The information string to be parsed.
 * @param index      The secondary index specification to be populated. The caller is responsible
 *                   for deallocating `index->path_vec`.
 *
 * @result           `true`, if successful.
 */
bool
parse_index_info(char *ns, char *index_str, index_param *index)
{
	bool res = false;

	if (index_str[0] == 0) {
		err("Empty index info in");
		goto cleanup0;
	}

	as_vector index_vec;
	as_vector_inita(&index_vec, sizeof (void *), 25);
	split_string(index_str, ':', false, &index_vec);

	index->ns = ns;
	index->set = NULL;
	index->name = NULL;
	index->type = INDEX_TYPE_INVALID;
	index->ctx = NULL;

	as_vector_init(&index->path_vec, sizeof (path_param), 25);

	char *path = NULL;
	path_type type = PATH_TYPE_INVALID;

	for (uint32_t i = 0; i < index_vec.size; ++i) {
		char *para = as_vector_get_ptr(&index_vec, i);
		char *equals = strchr(para, '=');

		if (equals == NULL) {
			err("Invalid secondary index parameter string %s (missing \"=\")", para);
			goto cleanup2;
		}

		*equals = 0;
		char *arg = equals + 1;

		if (strcmp(para, "set") == 0) {
			index->set = strcmp(arg, "NULL") == 0 ? NULL : arg;
		} else if (strcmp(para, "indexname") == 0) {
			index->name = arg;
		} else if (strcmp(para, "num_bins") == 0) {
			if (strcmp(arg, "1") != 0) {
				err("Multi-bin secondary indexes currently not supported, number of bins: %s",
						arg);
				goto cleanup2;
			}
		} else if (strcmp(para, "type") == 0) {
			if (strcasecmp(arg, "STRING") == 0) {
				type = PATH_TYPE_STRING;
			} else if (strcasecmp(arg, "TEXT") == 0) {
				type = PATH_TYPE_STRING;
			} else if (strcasecmp(arg, "NUMERIC") == 0) {
				type = PATH_TYPE_NUMERIC;
			} else if (strcasecmp(arg, "INT SIGNED") == 0) {
				type = PATH_TYPE_NUMERIC;
			} else if (strcasecmp(arg, "GEO2DSPHERE") == 0 || strcasecmp(arg, "GEOJSON") == 0) {
				type = PATH_TYPE_GEO2DSPHERE;
			} else {
				err("Invalid path type %s", arg);
				goto cleanup2;
			}
		} else if (strcmp(para, "indextype") == 0) {
			if (strcasecmp(arg, "LIST") == 0) {
				index->type = INDEX_TYPE_LIST;
			} else if (strcasecmp(arg, "MAPKEYS") == 0) {
				index->type = INDEX_TYPE_MAPKEYS;
			} else if (strcasecmp(arg, "MAPVALUES") == 0) {
				index->type = INDEX_TYPE_MAPVALUES;
			} else if (strcasecmp(arg, "NONE") == 0 || strcasecmp(arg, "DEFAULT") == 0) {
				index->type = INDEX_TYPE_NONE;
			} else {
				err("Invalid index type %s", arg);
				goto cleanup2;
			}
		} else if (strcmp(para, "bin") == 0) { 
			path = arg;
		} else if (strcmp(para, "context") == 0) {
			index->ctx = strcasecmp(arg, "NULL") == 0 ? NULL : arg;
		}
		if (path != NULL && type != PATH_TYPE_INVALID) {
			path_param tmp = { path, type };
			as_vector_append(&index->path_vec, &tmp);
			path = NULL;
			type = PATH_TYPE_INVALID;
		}
	}

	if (index->name == NULL) {
		err("Missing index name");
		goto cleanup2;
	}

	if (index->type == INDEX_TYPE_INVALID) {
		err("Missing index type in index %s", index->name);
		goto cleanup2;
	}

	if (index->path_vec.size != 1) {
		err("Invalid number of paths in index %s (%u)", index->name, index->path_vec.size);
		goto cleanup2;
	}

	res = true;
	goto cleanup1;

cleanup2:
	as_vector_destroy(&index->path_vec);

cleanup1:
	as_vector_destroy(&index_vec);

cleanup0:
	return res;
}

/*
 * Turns a string list of comma-delimited set names and turns them into a vector
 * of c strings.
 */
bool
parse_set_list(as_vector* dst, const char* set_list)
{
	uint64_t i = 0;
	while (1) {
		if (set_list[i] == '\'' || set_list[i] == '"') {
			char* end = strchr(set_list + i + 1, set_list[i]);
			if (end == NULL) {
				err("Missing terminating %c in set name", set_list[i]);
				return false;
			}

			uint64_t len = (uint64_t) (end - (set_list + i + 1));
			if (len >= AS_SET_MAX_SIZE) {
				err("Set name must be no longer than %d characters",
						AS_SET_MAX_SIZE - 1);
				return false;
			}
			char* slot = (char*) as_vector_reserve(dst);
			memcpy(slot, set_list + i + 1, len);
			slot[len] = '\0';

			i += len + 2;
		}
		else {
			char* end = strchrnul(set_list + i, ',');
			uint64_t len = (uint64_t) (end - (set_list + i));
			if (len >= AS_SET_MAX_SIZE) {
				err("Set name must be no longer than %d characters",
						AS_SET_MAX_SIZE - 1);
				return false;
			}
			char* slot = (char*) as_vector_reserve(dst);
			memcpy(slot, set_list + i, len);
			slot[len] = '\0';

			i += len;
		}

		if (set_list[i] == '\0') {
			break;
		}
		if (set_list[i] != ',') {
			err("Require ',' to delineate set names");
			return false;
		}
		i++;
	}
	return true;
}

/*
 * parses a base64 encoded binary string in environment variable "env_var_name"
 *
 * returns a pointer to a malloc-ed decoded string, or NULL on failure
 */
encryption_key_t*
parse_encryption_key_env(const char* env_var_name)
{
	uint8_t* pkey_data;
	uint32_t pkey_len;
	uint32_t encoded_len;

	char* pkey_env = getenv(env_var_name);

	if (pkey_env == NULL) {
		err("No environment variable \"%s\" found\n", env_var_name);
		return NULL;
	}

	encoded_len = (uint32_t) strlen(pkey_env);
	pkey_data = (uint8_t*) cf_malloc(cf_b64_decoded_buf_size(encoded_len));

	if (!cf_b64_validate_and_decode(pkey_env, encoded_len, pkey_data,
			&pkey_len)) {
		err("Unable to decode enviroment variable \"%s\" as base64\n",
				env_var_name);
		return NULL;
	}
	encryption_key_t* pkey = (encryption_key_t*)
		cf_malloc(sizeof(encryption_key_t));
	encryption_key_init(pkey, pkey_data, pkey_len);
	return pkey;
}

int
get_server_version(aerospike* as, server_version_t* version_info)
{
	as_error ae;
	char* response;

	if (aerospike_info_any(as, &ae, NULL, "version", &response) != AEROSPIKE_OK) {
		err("Error while querying server version - code %d:\n"
				"%s at %s:%d",
				ae.code, ae.message, ae.file, ae.line);
		return -1;
	}

	char* build_str = strstr(response, "build");
	if (build_str == NULL || strlen(build_str) <= 6) {
		err("Invalid info request response from server: %s\n", response);
		cf_free(response);
		return -1;
	}

	char* version_str = build_str + 6;
	if (sscanf(version_str, "%" PRIu32 ".%" PRIu32 ".%" PRIu32 ".%" PRIu32 "\n",
				&version_info->major, &version_info->minor,
				&version_info->patch, &version_info->build_id) != 4) {
		err("Invalid info request build number: %s\n", version_str);
		cf_free(response);
		return -1;
	}

	cf_free(response);
	return 0;
}

/*
 * Checks for availability of batch writes. Returns false if an error occurred
 * while checking.
 */
bool
server_has_batch_writes(aerospike* as, const server_version_t* version_info,
		bool* batch_writes_enabled)
{
	const char batch_idx_threads_param[] = "batch-index-threads";
	char* info_res;
	as_error ae;

	if (SERVER_VERSION_BEFORE(version_info, 6, 0)) {
		// batch writes not available
		*batch_writes_enabled = false;
		return true;
	}

	char info_str[] = "get-config:context=service";

	as_policy_info policy;
	as_policy_info_init(&policy);

	if (aerospike_info_any(as, &ae, &policy, info_str, &info_res) != AEROSPIKE_OK) {
		err("Failed to query server to check availability of batch writes\n");
		return false;
	}

	char* batch_index_threads = strstr(info_res, batch_idx_threads_param);
	if (batch_index_threads == NULL) {
		err("Server info response to %s is missing %s parameter\n", info_str,
				batch_idx_threads_param);
		ver("Response: %s", info_res);

		*batch_writes_enabled = false;
	}
	else {
		// param_val should be in the format "=<n idx threads>[;<more params>]"
		char* param_val = batch_index_threads +
			(sizeof(batch_idx_threads_param) - 1);
		if (param_val[0] != '=') {
			err("Invalid info response format: expected '=' to follow %s",
					batch_idx_threads_param);
			cf_free(info_res);
			return false;
		}

		char* endptr;
		uint64_t n_batch_threads = strtoul(param_val + 1, &endptr, 10);
		if (endptr == param_val + 1 || (*endptr != '\0' && *endptr != ';')) {
			*endptr = '\0';
			err("Invalid info response format: expected a number to follow "
					"\"%s=\", but got \"%s\"",
					batch_idx_threads_param, param_val + 1);
			cf_free(info_res);
			return false;
		}

		ver("Num batch index threads: %" PRIu64, n_batch_threads);

		*batch_writes_enabled = (n_batch_threads > 0);
	}

	cf_free(info_res);

	return true;
}

bool
as_key_move(as_key* dst, as_key* src)
{
	*dst = *src;
	if (!src->valuep) {
		return true;
	}
	
	// can't change the definition of as_key so
	// leaving this as an as_atomic instead of a c11 atomic
	if (as_load_uint32(&src->valuep->integer._.count) > 1) {
		//inf("Couldn't move record key values (reference count > 1).");
		return false;
	}

	if (src->valuep == &src->value) {
		dst->valuep = &dst->value;
	}

	return true;
}

bool
as_record_move(as_record* dst, as_record* src)
{
	// can't change the definition of as_record so
	// leaving this as an as_atomic instead of a c11 atomic
	if (as_load_uint32(&src->_._.count) > 1) {
		return false;
	}

	*dst = *src;
	return as_key_move(&dst->key, &src->key);
}

void
as_vector_swap(as_vector* v1, as_vector* v2)
{
	// copied from aerospike/as_vector.c
#define FLAGS_CREATED 2u

	void* list = v1->list;
	uint32_t capacity = v1->capacity;
	uint32_t size = v1->size;
	uint32_t item_size = v1->item_size;
	uint32_t flags = v1->flags & ~FLAGS_CREATED;

	v1->list = v2->list;
	v1->capacity = v2->capacity;
	v1->size = v2->size;
	v1->item_size = v2->item_size;
	v1->flags = (v1->flags & FLAGS_CREATED) | (v2->flags & ~FLAGS_CREATED);

	v2->list = list;
	v2->capacity = capacity;
	v2->size = size;
	v2->item_size = item_size;
	v2->flags = (v2->flags & FLAGS_CREATED) | flags;
}

#ifdef __APPLE__

char*
strchrnul(const char* s, int c_in)
{
	char* res = strchr(s, c_in);
	if (res == NULL) {
		res = strchr(s, '\0');
	}
	return res;
}

#endif /* __APPLE__ */


//==========================================================
// Local helpers.
//

/*
 * Determine the current thread's ID.
 */
static pid_t
thread_id(void)
{
#if !defined __APPLE__
	return (pid_t)syscall(SYS_gettid);
#elif MAC_OS_X_VERSION_MAX_ALLOWED < MAC_OS_X_VERSION_10_12
	return (pid_t)syscall(SYS_thread_selfid);
#else
	uint64_t tid;
	pthread_threadid_np(NULL, &tid);
	return (pid_t)tid;
#endif
}

as_exp*
exp_component_join_and_compile(as_exp_ops join_op, uint32_t n_ops,
		exp_component_t** components)
{
	uint32_t n_set_ops = 0;
	uint64_t total_size_bytes = 0;

	for (uint32_t i = 0; i < n_ops; i++) {
		exp_component_t* exp_comp = components[i];
		total_size_bytes += exp_comp->size;
		
		if (exp_comp->expr != NULL) {
			n_set_ops++;
		}
	}

	if (n_set_ops == 0) {
		// If nothing to be joined, return an empty expression (i.e. don't
		// filter).
		return NULL;
	}

	if (n_set_ops > 1) {
		// Only if there is more than one expression in the list, we join with
		// join_op
		total_size_bytes += 2 * sizeof(as_exp_entry);
	}

	as_exp_entry* table = (as_exp_entry*) cf_malloc(total_size_bytes);
	if (table == NULL) {
		err("Unable to malloc %" PRIu64 " bytes for as_exp_entry table",
				total_size_bytes);
		return EXP_ERR;
	}

	uint64_t table_offset = 0;

	if (n_set_ops > 1) {
		table[table_offset++] = (as_exp_entry) { .op = join_op };
	}

	for (uint32_t i = 0; i < n_ops; i++) {
		exp_component_t* exp_comp = components[i];

		if (exp_comp->expr != NULL) {
			memcpy(&table[table_offset], exp_comp->expr, exp_comp->size);
			table_offset += exp_comp->size / sizeof(as_exp_entry);
		}
	}

	if (n_set_ops > 1) {
		table[table_offset++] = (as_exp_entry) { .op = _AS_EXP_CODE_END_OF_VA_ARGS };
	}

	as_exp* compiled_exp = as_exp_compile(table,
			(uint32_t) (total_size_bytes / sizeof(as_exp_entry)));
	if (compiled_exp == NULL) {
		err("Failed to compile joined expression");
		compiled_exp = EXP_ERR;
	}

	cf_free(table);
	return compiled_exp;
}

void
tls_config_destroy(as_config_tls* tls)
{
	if (tls->cafile != NULL) {
		cf_free(tls->cafile);
	}

	if (tls->capath != NULL) {
		cf_free(tls->capath);
	}

	if (tls->protocols != NULL) {
		cf_free(tls->protocols);
	}

	if (tls->cipher_suite != NULL) {
		cf_free(tls->cipher_suite);
	}

	if (tls->cert_blacklist != NULL) {
		cf_free(tls->cert_blacklist);
	}

	if (tls->keyfile != NULL) {
		cf_free(tls->keyfile);
	}

	if (tls->keyfile_pw != NULL) {
		cf_free(tls->keyfile_pw);
	}

	if (tls->certfile != NULL) {
		cf_free(tls->certfile);
	}

	memset(tls, 0, sizeof(as_config_tls));
}

void
tls_config_clone(as_config_tls* clone, const as_config_tls* src)
{
	memcpy(clone, src, sizeof(as_config_tls));
	clone->cafile = safe_strdup(src->cafile);
	clone->capath = safe_strdup(src->capath);
	clone->protocols = safe_strdup(src->protocols);
	clone->cipher_suite = safe_strdup(src->cipher_suite);
	clone->cert_blacklist = safe_strdup(src->cert_blacklist);
	clone->keyfile = safe_strdup(src->keyfile);
	clone->keyfile_pw = safe_strdup(src->keyfile_pw);
	clone->certfile = safe_strdup(src->certfile);
}

void
sc_config_clone(sc_cfg* clone, const sc_cfg* src)
{
	memcpy(clone, src, sizeof(sc_cfg));
	clone->addr = safe_strdup(src->addr);
	clone->port = safe_strdup(src->port);
	sc_tls_clone(&clone->tls, &src->tls);
}

void
sc_config_destroy(sc_cfg* cfg)
{
	if (cfg->addr != NULL) {
		cf_free((char*) cfg->addr);
	}
	
	if (cfg->port != NULL) {
		cf_free((char*) cfg->port);
	}

	sc_tls_destroy(&cfg->tls);

	memset(cfg, 0, sizeof(sc_cfg));
}

void
sc_tls_clone(sc_tls_cfg* clone, const sc_tls_cfg* src)
{
	memcpy(clone, src, sizeof(sc_tls_cfg));
	clone->ca_string = safe_strdup(src->ca_string);
}

void
sc_tls_destroy(sc_tls_cfg* cfg)
{
	if (cfg->ca_string != NULL) {
		cf_free((char*) cfg->ca_string);
		cfg->ca_string = NULL;
	}

	memset(cfg, 0, sizeof(sc_tls_cfg));
}

char* read_file_as_string(const char* path)
{
    FILE* fptr;
    long flen;

    fptr = fopen(path, "rb");
	if (fptr == NULL) {
		err("failed to open %s", path);
		return NULL;
	}

    if (fseek(fptr, 0, SEEK_END) != 0) {
		err("failed to seek to end of %s", path);
		return NULL;
	}

    flen = ftell(fptr);
	if (flen < 0) {
		err("filed to get file length of %s", path);
		return NULL;
	}

    rewind(fptr);

    char* buf = (char*) cf_malloc(((unsigned long)flen) * sizeof(char));
	if (buf == NULL) {
		err("failed to allocate memory for file buff, path: %s", path);
		return NULL;
	}

    fread(buf, (unsigned long)flen, 1, fptr);
	if (ferror(fptr)) {
		cf_free(buf);
		err("failed to read %s", path);
		return NULL;
	}

    if (fclose(fptr) != 0) {
		cf_free(buf);
		err("failed closing %s", path);
		return NULL;
	}

    return buf;
}

int
get_and_set_secret_arg(sc_client* sc, char* path, char** res, bool* is_secret) {
	*is_secret = false;
	size_t secret_size = 0;

	if (path && !strncmp(SC_SECRETS_PATH_REFIX, path, strlen(SC_SECRETS_PATH_REFIX))) {

		if (!sc->cfg->addr || !sc->cfg->port) {
			err("--sa-address and --sa-port must be used when using secrets");
			return 1;
		}

		char* tmp_secret;
		sc_err sc_status = sc_secret_get_bytes(sc, path, (uint8_t**) &tmp_secret, &secret_size);
		if (sc_status.code == SC_OK) {
			tmp_secret[secret_size] = 0;
			*res = tmp_secret;
			*is_secret = true;
		}
		else {
			err("secret agent request failed err code: %d", sc_status.code);
			return 1;
		}
	}

	return 0;
}
