/*
 * Copyright 2015-2016 Aerospike, Inc.
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

#include <shared.h>
#include <spec.h>

#define DEFAULT_SPEC_FILE "spec.txt"    ///< The default specification file name.
#define DEFAULT_THREADS 4               ///< The default number of worker threads.
#define DEFAULT_CEILING 0               ///< The default TPS limit.
#define DEFAULT_KEY_TYPE KEY_TYPE_ANY   ///< The default key type.
#define DEFAULT_FUZZ false              ///< The default fuzzing setting.
#define DEFAULT_BENCH false             ///< The default benchmark more setting.

#define MAX_THREADS 1000                ///< The maximal number of worker threads.

#define BIN_NAME_FORMAT "bin-%08x"      ///< The template for creating bin names.
#define BIN_NAME_SIZE (4 + 8 + 1)       ///< The required buffer size for bin names (including the
                                        ///  the terminating NUL).

#define KEY_LENGTH 50                   ///< The length of generated string and BLOB keys.

struct job_node_s;
typedef struct job_node_s job_node;     ///< Describes a job, which is a record specification plus
                                        ///  a count. The command line arguments
                                        ///  `count-1 record-1 [...]` are turned into a linked list
                                        ///  of these.

///
/// Describes a job, which is a record specification plus a count. The command line arguments
/// `count-1 record-1 [...]` are turned into a linked list of these.
///
/// The jobs are fed sequentially to the worker threads.
///
struct job_node_s {
	job_node *next;     ///< Pointer for the linked list of jobs.
	uint64_t count;     ///< The count for this job.
	rec_node *record;   ///< The record specification for this job.
};

///
/// The type of key to generate.
///
typedef enum {
	KEY_TYPE_ANY,       ///< Randomly picks between an integer, string, and BLOB key.
	KEY_TYPE_INTEGER,   ///< An integer key.
	KEY_TYPE_STRING,    ///< A string key.
	KEY_TYPE_BYTES      ///< A BLOB key.
} key_type;

///
/// Encapsulates the arguments passed to a worker thread.
///
struct fill_context_s {
	const char *host;               ///< The host to connect to.
	uint16_t port;                  ///< The port to connect to.
	const char *user;               ///< The user to connect as.
	const char *password;           ///< The password to connect with.
	const char *namespace;          ///< The namespace to write to.
	const char *set;                ///< The set to write to.
	const job_node *job;            ///< The job to be executed.
	bool fuzz;                      ///< Enables fuzzing.
	bool bench;                     ///< Enables benchmark mode, i.e., speed optimization by
	                                ///  re-using the same generated data for multiple records.
	key_type key_type;              ///< The type of key to generate.
	volatile uint64_t remaining;    ///< The number of remaining records to be put.
	volatile uint64_t total;        ///< The total number of records put so far.
	volatile uint64_t quota;        ///< The current limit for @ref total for throttling. This is
	                                ///  periodically increased by the counter thread to raise
	                                ///  the limit according to the TPS limit.
};

typedef struct fill_context_s fill_context;     ///< Encapsulates the arguments passed to a worker
                                                ///  thread.

static pthread_mutex_t mutex;                           ///< Provides mutual exclusion for worker
                                                        ///  threads.
static volatile uint64_t rand_state;                    ///< State of the linear congruential
                                                        ///  generator (LCG).
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;  ///< Provides signaling for the throttling
                                                        ///  mechanism.

///
/// A wrapper around `pthread_mutex_lock()` that exits on errors. Uses @ref mutex.
///
static void
lock()
{
	if (pthread_mutex_lock(&mutex) != 0) {
		fprintf(stderr, "cannot lock mutex\n");
		exit(EXIT_FAILURE);
	}
}

///
/// A wrapper around `pthread_mutex_unlock()` that exits on errors. Uses @ref mutex.
///
static void
unlock()
{
	if (pthread_mutex_unlock(&mutex) != 0) {
		fprintf(stderr, "cannot unlock mutex\n");
		exit(EXIT_FAILURE);
	}
}

///
/// A wrapper around `pthread_cond_wait()` that exits on errors. Uses @ref mutex and @ref cond.
///
static void
wait_signal()
{
	if (pthread_cond_wait(&cond, &mutex) != 0) {
		fprintf(stderr, "cannot wait for signal\n");
		exit(EXIT_FAILURE);
	}
}

///
/// A wrapper around `pthread_cond_broadcast()` that exits on errors. Uses @ref mutex and @ref cond.
///
static void
send_signal()
{
	if (pthread_cond_broadcast(&cond) != 0) {
		fprintf(stderr, "cannot send signal\n");
		exit(EXIT_FAILURE);
	}
}

///
/// A wrapper around `cf_malloc()` that exits on errors.
///
static void *
allocate(size_t size)
{
	void *mem = cf_malloc(size);

	if (mem == NULL) {
		fprintf(stderr, "cannot allocate memory\n");
		exit(EXIT_FAILURE);
	}

	return mem;
}

///
/// A 48-bit linear congruential generator (LCG).
///
/// Note that the upper bits of an LCG are "more random" than the lower bits. So, if you need
/// random 8-bit values, for example, then use the uppermost 8 bits as in `rand48() >> 40`.
///
/// @result A 48-bit pseudo-random value.
///
static uint64_t
rand48()
{
	lock();
	uint64_t x = rand_state * 6364136223846793005 + 1;
	rand_state = x;
	unlock();
	return x >> 16;
}

///
/// Generates a pseudo-random 64-bit signed integer.
///
/// @result A 64-bit pseudo-random signed integer.
///
static int64_t
rand64()
{
	return (int64_t)(rand48() * rand48());
}

///
/// Recursively frees a tree of @ref type_node.
///
/// @param node  The root of the tree to be freed.
///
static void
free_type(type_node *node)
{
	if (node->children[0] != NULL) {
		free_type(node->children[0]);
	}

	if (node->children[1] != NULL) {
		free_type(node->children[1]);
	}

	cf_free(node);
}

///
/// Frees a linked list of @ref bin_node. Invokes free_type() to free any referenced @ref type_node.
///
/// @param node  The first node in the linked list.
///
static void
free_bins(bin_node *node)
{
	while (node != NULL) {
		if (node->type != NULL) {
			free_type(node->type);
		}

		bin_node *next = node->next;
		cf_free(node);
		node = next;
	}
}

///
/// Frees a linked list of @ref rec_node. Invokes free_bins() to free any referenced @ref bin_node.
///
/// @param node  The first node in the linked list.
///
static void
free_records(rec_node *node)
{
	while (node != NULL) {
		if (node->bins != NULL) {
			free_bins(node->bins);
		}

		rec_node *next = node->next;
		cf_free(node);
		node = next;
	}
}

///
/// Frees a linked list of @ref job_node.
///
/// @param node  The first node in the linked list.
///
static void
free_jobs(job_node *node)
{
	while (node != NULL) {
		job_node *next = node->next;
		cf_free(node);
		node = next;
	}
}

///
/// Indents by writing space characters to the given file descriptor.
///
/// @param out    The file descriptor to write to.
/// @param level  The indentation level.
///
static void
indent(FILE *out, int32_t level)
{
	for (int32_t i = 0; i < 4 * level + 8; ++i) {
		fputc(' ', out);
	}
}

///
/// Recursively prints out a tree of @ref type_node.
///
/// @param out    The file descriptor to output to.
/// @param node   The root of the tree to be printed.
/// @param level  The current indentation level.
///
static void
print_type_rec(FILE *out, const type_node *node, int32_t level)
{
	indent(out, level);

	if (node->type == NIL) {
		fprintf(out, "NIL\n");
		return;
	}

	if (node->type == INTEGER) {
		fprintf(out, "random integer\n");
		return;
	}

	if (node->type == DOUBLE) {
		fprintf(out, "random double\n");
		return;
	}

	if (node->type == STRING) {
		fprintf(out, "random string, length: %" PRIu32 "\n", node->count);
		return;
	}

	if (node->type == BYTES) {
		fprintf(out, "random bytes, length: %" PRIu32 "\n", node->count);
		return;
	}

	if (node->type == LIST) {
		fprintf(out, "list, length: %" PRIu32 ", elements of type:\n", node->count);
		print_type_rec(out, node->children[0], level + 1);
		return;
	}

	if (node->type == MAP) {
		fprintf(out, "map, size: %" PRIu32 "\n", node->count);
		indent(out, level);
		fprintf(out, "keys of type:\n");
		print_type_rec(out, node->children[0], level + 1);
		indent(out, level);
		fprintf(out, "values of type:\n");
		print_type_rec(out, node->children[1], level + 1);
		return;
	}
}

///
/// Recursively prints out a tree of @ref type_node.
///
/// @param out    The file descriptor to output to.
/// @param node   The root of the tree to be printed.
///
static void
print_type(FILE *out, const type_node *node)
{
	print_type_rec(out, node, 0);
}

///
/// Prints out a linked list of @ref bin_node. Invokes print_type() to print out any referenced
/// @ref type_node.
///
/// @param node  The first node in the linked list.
///
static void
print_bins(const bin_node *node)
{
	while (node != NULL) {
		fprintf(stdout, "    %" PRIu32 " bin%s of type:\n", node->count,
				node->count != 1 ? "s" : "");
		print_type(stdout, node->type);
		node = node->next;
	}
}

///
/// Prints out a @ref rec_node. Invokes print_bins() to print out the referenced list of
/// @ref bin_node.
///
/// @param node  The node to be printed.
///
static void
print_record(const rec_node *node)
{
	fprintf(stdout, "record spec \"%s\"\n", node->name);
	print_bins(node->bins);
}

///
/// Prints out a linked list of @ref rec_node. Invokes print_record() to print out each individual
/// @ref rec_node.
///
/// @param node  The first node in the linked list.
///
static void
print_records(const rec_node *node)
{
	while (node != NULL) {
		print_record(node);
		fputc('\n', stdout);
		node = node->next;
	}
}

///
/// Displays an Aerospike client error with a custom error message.
///
/// @param err     The Aerospike client error.
/// @param format  The format string for the custom error message.
///
static void
show_error(as_error *err, const char *format, ...)
{
	va_list args;
	char buffer[1000];
	va_start(args, format);
	size_t len = (size_t)vsnprintf(buffer, sizeof buffer, format, args);
	va_end(args);

	if (len < sizeof buffer - 1) {
		snprintf(buffer + len, sizeof buffer - len, " - code %d: %s at %s:%d", err->code,
				err->message, err->file, err->line);
	}

	fprintf(stderr, "%s\n", buffer);
}

static as_val *generate(const type_node *type, bool fuzz);

///
/// Generates a pseudo-random 64-bit `as_integer`.
///
/// @result A pseudo-random 64-bit `as_integer`.
///
static as_val *
generate_integer()
{
	return (as_val *)as_integer_new(rand64());
}

///
/// Generates a pseudo-random double-precision`as_double`.
///
/// @result A pseudo-random double-precision `as_double`.
///
static as_val *
generate_double()
{
	double val;

	switch (rand48() % 1000) {
	case 0:
		// NaN
		val = 1.0 / 0.0 - 1.0 / 0.0;
		break;

	case 1:
		// +Inf
		val = 1.0 / 0.0;
		break;

	case 2:
		// -Inf
		val = -1.0 / 0.0;
		break;

	default: {
		int64_t val1 = (int64_t)rand48();
		int64_t val2 = (int64_t)rand48();

		if (rand48() % 2 == 0) {
			val1 = -val1;
		}

		if (rand48() % 2 == 0) {
			val2 = -val2;
		}

		val = (double)val1 / (double)val2;
		break;
	}
	}

	return (as_val *)as_double_new(val);
}

///
/// Fills the given buffer with a pseudo-random string of the given size.
///
/// If fuzzing is disabled, the string will be alpha-numeric. Otherwise, the string will consist of
/// pseudo-random bytes - either including or excluding NUL.
///
/// @param buffer     The output buffer for the generated string.
/// @param size       The size of the string to be generated.
/// @param fuzz       Enables fuzzing.
/// @param allow_nul  Allows NUL bytes, when fuzzing is enabled.
///
static void
get_string(char *buffer, size_t size, bool fuzz, bool allow_nul)
{
	for (size_t i = 0; i < size; ++i) {
		if (!fuzz) {
			// upper bits of a LCG are "more random" than lower bits, so shift
			buffer[i] = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789_-"
					[(rand48() >> 42) & 0x3f];
		} else {
			uint64_t x = (rand48() >> 40) & 0xff;
			buffer[i] = (char)(allow_nul || x != 0 ? x : 1);
		}
	}
}

///
/// Generates a pseudo-random `as_string` of the given size.
///
/// @param size  The size of the `as_string` to be generated.
/// @param fuzz  Enables fuzzing.
///
/// @result      A pseudo-random `as_string`.
///
static as_val *
generate_string(uint32_t size, bool fuzz)
{
	char *string = allocate(size + 1);

	get_string(string, size, fuzz, true);
	((char *)string)[size] = 0;

	return (as_val *)as_string_new_wlen(string, size, true);
}

///
/// Fills the given buffer with a pseudo-random BLOB of the given size.
///
/// @param buffer  The output buffer for the generated BLOB.
/// @param size    The size of the BLOB to be generated.
///
static void
get_bytes(uint8_t *buffer, size_t size)
{
	for (size_t i = 0; i < size; ++i) {
		buffer[i] = (uint8_t)(rand48() >> 40);
	}
}

///
/// Generates a pseudo-random `as_bytes` of the given size.
///
/// @param size  The size of the `as_bytes` to be generated.
///
/// @result      A pseudo-random `as_bytes`.
///
static as_val *
generate_bytes(uint32_t size)
{
	uint8_t *bytes = allocate(size);
	get_bytes(bytes, size);
	return (as_val *)as_bytes_new_wrap(bytes, size, true);
}

///
/// Generates a pseudo-random `as_arraylist` of the given size, containing elements of the given
/// type.
///
/// Recursively invokes generate() to pseudo-randomly generate the list elements.
///
/// @param size      The number of elements in the `as_arraylist` to be generated.
/// @param val_type  The type of the list elements.
/// @param fuzz      Enables fuzzing.
///
/// @result          A pseudo-random `as_arraylist`.
///
static as_val *
generate_list(uint32_t size, const type_node *val_type, bool fuzz)
{
	as_arraylist *list = as_arraylist_new(1, 16384);

	if (list == NULL) {
		return NULL;
	}

	for (uint32_t i = 0; i < size; ++i) {
		as_val *val = generate(val_type, fuzz);

		if (val == NULL) {
			as_arraylist_destroy(list);
			return NULL;
		}

		if (as_arraylist_append(list, val) < 0) {
			fprintf(stderr, "cannot populate list, element is:\n");
			print_type_rec(stderr, val_type, 1);
			as_val_destroy(val);
			as_arraylist_destroy(list);
			return NULL;
		}
	}

	return (as_val *)list;
}

///
/// Generates a pseudo-random `as_hashmap` of the given size, containing keys and values of the
/// given types.
///
/// Recursively invokes generate() to pseudo-randomly generate the keys and values.
///
/// @param size      The number of elements in the `as_arraylist` to be generated.
/// @param key_type  The type of the keys.
/// @param val_type  The type of the values.
/// @param fuzz      Enables fuzzing.
///
/// @result          A pseudo-random `as_hashmap`.
///
static as_val *
generate_map(uint32_t size, const type_node *key_type, const type_node *val_type, bool fuzz)
{
	as_hashmap *map = as_hashmap_new(64);

	if (map == NULL) {
		return NULL;
	}

	for (uint32_t i = 0; i < size; ++i) {
		as_val *key_val = generate(key_type, fuzz);

		if (key_val == NULL) {
			as_hashmap_destroy(map);
			return NULL;
		}

		as_val *val_val = generate(val_type, fuzz);

		if (val_val == NULL) {
			as_val_destroy(key_val);
			as_hashmap_destroy(map);
			return NULL;
		}

		if (as_hashmap_set(map, key_val, val_val) < 0) {
			fprintf(stderr, "cannot populate hash map, key is:\n");
			print_type_rec(stderr, key_type, 1);
			fprintf(stderr, "value is:\n");
			print_type_rec(stderr, val_type, 1);
			as_val_destroy(key_val);
			as_val_destroy(val_val);
			as_hashmap_destroy(map);
			return NULL;
		}
	}

	return (as_val *)map;
}

///
/// Entry point for generating a pseudo-random value of the given type.
///
/// Depending on the requested type, dispatches to generate_integer(), generate_string(),
/// generate_bytes(), generate_list(), or generate_map().
///
/// @param type  The type of the value to be generated.
/// @param fuzz  Enables fuzzing.
///
/// @result      Depending on the requested type, an `as_integer`, `as_string`, `as_bytes`,
///              `as_list`, or `as_map`.
///
static as_val *
generate(const type_node *type, bool fuzz)
{
	switch (type->type) {
	case NIL:
		return NULL;

	case INTEGER:
		return generate_integer();

	case DOUBLE:
		return generate_double();

	case STRING:
		return generate_string(type->count, fuzz);

	case BYTES:
		return generate_bytes(type->count);

	case LIST:
		return generate_list(type->count, type->children[0], fuzz);

	case MAP:
		return generate_map(type->count, type->children[0], type->children[1], fuzz);
	}

	return NULL;
}

///
/// Initializes the given key.
///
/// @param key        The key to be initialized.
/// @param namespace  The namespace to be used in the key.
/// @param set        The set to be used in the key.
/// @param type       The type of the pseudo-random key value to be generated for the key.
/// @param fuzz       Enables fuzzing.
///
/// @result           `true`, if successful.
///
static bool
init_key(as_key *key, const char *namespace, const char *set, key_type type, bool fuzz)
{
	static key_type map[3] = {
		KEY_TYPE_INTEGER, KEY_TYPE_STRING, KEY_TYPE_BYTES
	};

	if (type == KEY_TYPE_ANY) {
		uint32_t index = (uint32_t)rand48() % 3;
		type = map[index];
	}

	void *data;
	as_string *string;

	switch (type) {
	case KEY_TYPE_ANY:
		break;

	case KEY_TYPE_INTEGER:
		as_key_init_int64(key, namespace, set, rand64());
		break;

	case KEY_TYPE_STRING:
		data = allocate(KEY_LENGTH + 1);

		get_string(data, KEY_LENGTH, fuzz, true);
		((char *)data)[KEY_LENGTH] = 0;

		string = as_string_new_wlen(data, KEY_LENGTH, true);

		if (string == NULL) {
			fprintf(stderr, "error while allocating string key value\n");
			cf_free(data);
			return false;
		}

		as_key_init_value(key, namespace, set, (as_key_value *)string);
		break;

	case KEY_TYPE_BYTES:
		data = allocate(KEY_LENGTH);
		get_bytes(data, KEY_LENGTH);
		as_key_init_rawp(key, namespace, set, data, KEY_LENGTH, true);
		break;
	}

	return true;
}

///
/// Populates a record according to a job's record specification.
///
/// @param context     The fill context that, among other things, points to the job to be executed
///                    and, thus, indirectly to the record specification.
/// @param rec         The record to be populated.
/// @param name_count  Counts the number of generated unique bin names so that we can remain below
///                    the bin name quota imposed by `asd`.
///
/// @result            `true`, if successful.
///
static bool
create_record(fill_context *context, as_record *rec, uint32_t *name_count)
{
	bool res = false;
	uint32_t bin_count = 0;

	for (bin_node *bin = context->job->record->bins; bin != NULL; bin = bin->next) {
		bin_count += bin->count;
	}

	if (bin_count > 65535) {
		fprintf(stderr, "too many bins\n");
		goto cleanup0;
	}

	as_record_init(rec, (uint16_t)bin_count);
	uint32_t walker = 0;

	for (bin_node *bin = context->job->record->bins; bin != NULL; bin = bin->next) {
		for (uint32_t b = 0; b < bin->count; ++b) {
			char bin_name[BIN_NAME_SIZE];

			// only generate up to 250 different bin names per thread to stay
			// within asd's bin name quota
			if (!context->fuzz || *name_count >= 250) {
				snprintf(bin_name, sizeof bin_name, BIN_NAME_FORMAT, walker++);
			} else {
				get_string(bin_name, sizeof bin_name - 1, true, false);
				bin_name[sizeof bin_name - 1] = 0;
				++(*name_count);
			}

			as_val *val = NULL;

			if (bin->type->type != NIL && (val = generate(bin->type, context->fuzz)) == NULL) {
				fprintf(stderr, "cannot generate bin value\n");
				goto cleanup1;
			}

			bool ok = false;

			switch (bin->type->type) {
			case NIL:
				ok = as_record_set_nil(rec, bin_name);
				break;

			case INTEGER:
				ok = as_record_set_integer(rec, bin_name, (as_integer *)val);
				break;

			case DOUBLE:
				ok = as_record_set_as_double(rec, bin_name, (as_double *)val);
				break;

			case STRING:
				ok = as_record_set_string(rec, bin_name, (as_string *)val);
				break;

			case BYTES:
				ok = as_record_set_bytes(rec, bin_name, (as_bytes *)val);
				break;

			case LIST:
				ok = as_record_set_list(rec, bin_name, (as_list *)val);
				break;

			case MAP:
				ok = as_record_set_map(rec, bin_name, (as_map *)val);
				break;
			}

			if (!ok) {
				fprintf(stderr, "cannot populate bin\n");
				goto cleanup1;
			}
		}
	}

	res = true;
	goto cleanup0;

cleanup1:
	as_record_destroy(rec);

cleanup0:
	return res;
}

///
/// Main worker thread function.
///
///   - Gets the @ref fill_context that it is passed. The fill context contains (among other things)
///     the job to be executed. Which, in turn, contains (among other things) a record
///     specification.
///   - Connects to the Aerospike server.
///   - Pseudo-randomly populates a record according to the record specification from the
///     job / fill context.
///   - Initializes a key.
///   - Puts the populated record using the initialized key.
///   - Interates.
///
/// In benchmark mode, to speed things up, the populated record is kept. If benchmark mode is disabled,
/// then the record and the linked list are regenerated from scratch for each iteration.
///
/// @param data  The @ref fill_context passed to the thread.
///
/// @result      `0` on success, `1` on failure.
///
static void *
fill_worker(void *data)
{
	void *res = (void *)0;
	fill_context *context = data;
	as_config conf;
	as_config_init(&conf);
	conf.conn_timeout_ms = TIMEOUT;
	as_config_add_host(&conf, context->host, context->port);

	if (context->user != NULL && context->password != NULL) {
		as_config_set_user(&conf, context->user, context->password);
	}

	aerospike as;
	aerospike_init(&as, &conf);
	as_error err;

	if (aerospike_connect(&as, &err) != AEROSPIKE_OK) {
		show_error(&err, "error while connecting to %s:%d", context->host, context->port);
		goto cleanup1;
	}

	as_record rec;
	uint32_t name_count = 0;

	if (!create_record(context, &rec, &name_count)) {
		fprintf(stderr, "error while creating record data\n");
		goto cleanup2;
	}

	as_policy_write policy;
	as_policy_write_init(&policy);
	policy.key = AS_POLICY_KEY_SEND;
	policy.exists = AS_POLICY_EXISTS_CREATE;
	policy.base.total_timeout = TIMEOUT;

	while (true) {
		lock();

		if (context->quota > 0) {
			while (context->total >= context->quota && context->remaining > 0) {
				wait_signal();
			}
		}

		bool stop = context->remaining == 0;

		if (!stop) {
			if (context->quota > 0) {
				++context->total;
			}

			--context->remaining;
		}

		unlock();

		if (stop) {
			break;
		}

		as_key key;

		if (!init_key(&key, context->namespace, context->set, context->key_type, context->fuzz)) {
			goto cleanup3;
		}

		if (as_record_numbins(&rec) > 0 &&
				aerospike_key_put(&as, &err, &policy, &key, &rec) != AEROSPIKE_OK) {
			show_error(&err, "error while setting record on %s:%d\n", context->host, context->port);
			as_key_destroy(&key);
			goto cleanup3;
		}

		as_key_destroy(&key);

		if (!context->bench) {
			as_record_destroy(&rec);

			if (!create_record(context, &rec, &name_count)) {
				fprintf(stderr, "error while recreating record data\n");
				goto cleanup2;
			}
		}
	}

	res = (void *)1;

cleanup3:
	as_record_destroy(&rec);

cleanup2:
	if (aerospike_close(&as, &err) != AEROSPIKE_OK) {
		show_error(&err, "error while closing connection");
	}

cleanup1:
	aerospike_destroy(&as);

	if (res == (void *)0) {
		lock();
		context->remaining = 0;
		unlock();
	}

	return res;
}

///
/// Processes a single job.
///
///   - Populates a @ref fill_context for the job.
///   - Spawns the worker threads.
///   - Outputs progress information until all worker threads are done.
///
/// @param host       The host to connect to.
/// @param port       The port to connect to.
/// @param user       The user to connect as.
/// @param password   The password to connect with.
/// @param threads    The number of worker threads to spawn.
/// @param ceiling    The TPS limit.
/// @param fuzz       Enables fuzzing.
/// @param bench      Enables benchmark mode.
/// @param key_type   The type of key to generate.
/// @param namespace  The namespace to write to.
/// @param set        The set to write to.
/// @param job        The job to be executed.
///
/// @result           `true`, if successful.
///
static bool
fill(const char *host, uint16_t port, const char *user, const char *password, uint32_t threads,
		uint32_t ceiling, bool fuzz, bool bench, key_type key_type, const char *namespace,
		const char *set, const job_node *job)
{
	bool res = false;

	fprintf(stdout, "--------------- adding %" PRIu64" record%s to %s:%s on %s:%d\n\n",
			job->count, job->count != 1 ? "s" : "", namespace, set, host, port);
	print_record(job->record);
	fputc('\n', stdout);

	fill_context context;
	context.host = host;
	context.port = port;
	context.user = user;
	context.password = password;
	context.namespace = namespace;
	context.set = set;
	context.job = job;
	context.fuzz = fuzz;
	context.bench = bench;
	context.key_type = key_type;
	context.remaining = job->count;
	context.total = 0;
	context.quota = ceiling;
	pthread_t handles[threads];
	uint32_t actual;

	for (actual = 0; actual < threads; ++actual) {
		if (pthread_create(&handles[actual], NULL, fill_worker, &context) != 0) {
			fprintf(stderr, "cannot create thread\n");
			goto cleanup1;
		}
	}

	cf_clock last_time = cf_getms();
	lock();
	uint64_t last_count = context.remaining;
	unlock();

	while (true) {
		sleep(1);

		cf_clock now_time = cf_getms();
		lock();
		uint64_t now_count = context.remaining;

		if (ceiling > 0) {
			context.quota += ceiling * 1000 / (uint32_t)(now_time - last_time);
			send_signal();
		}

		unlock();
		fprintf(stdout, "progress is %" PRIu64 "%% (%" PRIu64 " TPS)\n",
				(job->count - now_count) * 100 / job->count,
				(last_count - now_count) * 1000 / (uint32_t)(now_time - last_time));

		if (now_count == 0) {
			break;
		}

		last_time = now_time;
		last_count = now_count;
	}

	fputc('\n', stdout);
	res = true;

cleanup1:
	lock();
	context.remaining = 0;
	unlock();

	for (uint32_t i = 0; i < actual; ++i) {
		void *result;

		if (pthread_join(handles[i], &result) != 0) {
			fprintf(stderr, "cannot join thread\n");
			res = false;
			continue;
		}

		if (result != (void *)1) {
			res = false;
		}
	}

	return res;
}

///
/// Reads the given file.
///
/// @param path  The path of the file to be read.
///
/// @result      The file data, NUL-terminated. Or `NULL`, in case of an error.
///
static char *
read_file(const char *path)
{
	char *buffer = NULL;
	FILE *fh = fopen(path, "r");

	if (fh == NULL) {
		fprintf(stderr, "cannot open spec file %s\n", path);
		goto cleanup0;
	}

	off_t file_size;

	if (fseek(fh, 0, SEEK_END) < 0 || (file_size = ftell(fh)) < 0 || fseek(fh, 0, SEEK_SET) < 0) {
		fprintf(stderr, "cannot determine spec file size\n");
		goto cleanup1;
	}

	buffer = allocate((size_t)file_size + 1);

	if (fread(buffer, (size_t)file_size, 1, fh) != 1) {
		fprintf(stderr, "cannot read spec file\n");
		goto cleanup2;
	}

	buffer[file_size] = 0;
	fclose(fh);
	return buffer;

cleanup2:
	cf_free(buffer);

cleanup1:
	fclose(fh);

cleanup0:
	return NULL;
}

///
/// Displays usage information.
///
static void
usage()
{
	fprintf(stderr,
			"usage: fill [-h host] [-p port] [-U user] [-P password] [-f spec-file]\n");
	fprintf(stderr,
			"            [-t threads] [-c tps-ceiling] [-k key-type] [-b] [-z]\n");
	fprintf(stderr,
			"            namespace set count-1 record-1 [count-2 record-2 [count-3 ...]]\n");
	fprintf(stderr,
			"       where threads < %u, key-type in { integer, string, bytes }\n\n",
			MAX_THREADS);
	fprintf(stderr,
			"   or: fill [-f spec-file] -l\n");
}

///
/// It all starts here.
///
int32_t
main(int32_t argc, char *argv[])
{
	int32_t res = EXIT_FAILURE;
	opterr = 0;
	const char *host_arg = DEFAULT_HOST;
	uint16_t port_arg = DEFAULT_PORT;
	const char *user_arg = NULL;
	const char *password_arg = NULL;
	const char *spec_file_arg = DEFAULT_SPEC_FILE;
	bool list = false;
	uint32_t threads_arg = DEFAULT_THREADS;
	uint32_t ceiling_arg = DEFAULT_CEILING;
	bool fuzz_arg = DEFAULT_FUZZ;
	bool bench_arg = DEFAULT_BENCH;
	key_type key_type_arg = DEFAULT_KEY_TYPE;
	int32_t opt;

	setlinebuf(stdout);

	while ((opt = getopt(argc, argv, ":h:p:U:P:f:t:c:k:bzl")) >= 0) {
		switch (opt) {
		case '?':
			fprintf(stderr, "invalid option: -%c\n", optopt);
			usage();
			goto cleanup0;

		case ':':
			fprintf(stderr, "missing argument to option -%c\n", optopt);
			usage();
			goto cleanup0;

		case 'h':
			host_arg = optarg;
			break;

		case 'p': {
			char *end;
			port_arg = (uint16_t)strtoul(optarg, &end, 10);

			if (*end != 0) {
				fprintf(stderr, "invalid port value: %s\n", optarg);
				usage();
				goto cleanup0;
			}

			break;
		}

		case 'U':
			user_arg = optarg;
			break;

		case 'P':
			password_arg = optarg;
			break;

		case 'f':
			spec_file_arg = optarg;
			break;

		case 't': {
			char *end;
			threads_arg = (uint32_t)strtoul(optarg, &end, 10);

			if (*end != 0 || threads_arg > MAX_THREADS) {
				fprintf(stderr, "invalid threads value: %s\n", optarg);
				usage();
				goto cleanup0;
			}

			break;
		}

		case 'c': {
			char *end;
			ceiling_arg = (uint32_t)strtoul(optarg, &end, 10);

			if (*end != 0) {
				fprintf(stderr, "invalid ceiling value: %s\n", optarg);
				usage();
				goto cleanup0;
			}

			break;
		}

		case 'k':
			if (strcmp(optarg, "integer") == 0) {
				key_type_arg = KEY_TYPE_INTEGER;
			} else if (strcmp(optarg, "string") == 0) {
				key_type_arg = KEY_TYPE_STRING;
			} else if (strcmp(optarg, "bytes") == 0) {
				key_type_arg = KEY_TYPE_BYTES;
			} else {
				fprintf(stderr, "invalid key type value: %s\n", optarg);
				usage();
				goto cleanup0;
			}

			break;

		case 'b':
			bench_arg = true;
			break;

		case 'z':
			fuzz_arg = true;
			break;

		case 'l':
			list = true;
			break;
		}
	}

	char *buffer;
	rec_node *records;

	buffer = read_file(spec_file_arg);

	if (buffer == NULL) {
		goto cleanup0;
	}

	if (!parse(buffer, &records)) {
		goto cleanup1;
	}

	if (list) {
		print_records(records);
		res = 0;
		goto cleanup2;
	}

	bool missing = false;
	const char *namespace = NULL; // for older GCCs
	const char *set = NULL; // dto.

	if (optind == argc) {
		fprintf(stderr, "missing namespace\n");
		missing = true;
	} else {
		namespace = argv[optind++];
	}

	if (optind == argc) {
		fprintf(stderr, "missing set\n");
		missing = true;
	} else {
		set = argv[optind++];
	}

	if (missing) {
		usage();
		goto cleanup2;
	}

	job_node *jobs = NULL;
	job_node **insert = &jobs;

	while (optind < argc) {
		char *end;
		uint64_t count = strtoul(argv[optind], &end, 10);

		if (*end != 0) {
			fprintf(stderr, "invalid record count argument: %s\n", argv[optind]);
			usage();
			goto cleanup2;
		}

		++optind;

		if (optind == argc) {
			fprintf(stderr, "missing record structure argument\n");
			usage();
			goto cleanup2;
		}

		rec_node *record = NULL;

		for (rec_node *walker = records; walker != NULL; walker = walker->next) {
			if (strcmp(walker->name, argv[optind]) == 0) {
				record = walker;
				break;
			}
		}

		if (record == NULL) {
			fprintf(stderr, "record structure \"%s\" not found in file %s\n", argv[optind],
					spec_file_arg);
			usage();
			goto cleanup2;
		}

		++optind;
		*insert = allocate(sizeof (job_node));
		memset(*insert, 0, sizeof (job_node));
		(*insert)->count = count;
		(*insert)->record = record;
		insert = &(*insert)->next;
	}

	rand_state = (uint64_t)time(NULL) * 10000000;
	pthread_mutex_init(&mutex, NULL);

	for (job_node *job = jobs; job != NULL; job = job->next) {
		if (!fill(host_arg, port_arg, user_arg, password_arg, threads_arg, ceiling_arg, fuzz_arg,
				bench_arg, key_type_arg, namespace, set, job)) {
			fprintf(stderr, "error while filling\n");
			goto cleanup3;
		}
	}

	res = EXIT_SUCCESS;

cleanup3:
	free_jobs(jobs);

cleanup2:
	free_records(records);

cleanup1:
	cf_free(buffer);

cleanup0:
	return res;
}
