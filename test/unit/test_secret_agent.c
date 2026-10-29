
#include <check.h>
#include <arpa/inet.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include <jansson.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <backup.h>
#include <conf.h>
#include <restore.h>

#include "backup_tests.h"


#define WORKING_DIR "test/unit"
#define CONF_FILE WORKING_DIR "/tmp_sa.conf"
#define LATER_CONF_FILE WORKING_DIR "/tmp_sa_later.conf"
#define INCLUDE_LATER "[include]\nfile = \"" LATER_CONF_FILE "\"\n"
#define INCLUDE_DIR WORKING_DIR "/tmp_sa_dir"
#define INCLUDE_DIR_FILE INCLUDE_DIR "/bad.conf"
#define OUT_FILE WORKING_DIR "/tmp_sa_out"
#define CA_CERT_FILE WORKING_DIR "/tmp_sa_ca.pem"
#define CA_FILE "test/test_key.pem"
#define CA_FILE2 "test/test_key2.pem"
#define NO_CA_FILE "test/no_such_ca.pem"
#define SA_MAGIC 0x51dec1cc
#define TLS_HANDSHAKE 0x16
#define SECRET_REPLY "{\"SecretValue\":\"MTI3LjAuMC4x\"}"
#define AGENT_ERROR "no such resource or key"
#define ERROR_REPLY "{\"Error\":\"" AGENT_ERROR "\"}"
#define SA_CAFILE_DEPRECATED \
	"Argument --sa-cafile is deprecated. Use --sa-ca-file instead."
#define TIMEOUT_EXPECTED ", expected an integer from 1 to 2147483647"
#define PORT_EXPECTED ", expected an integer from 1 to 65535"
#define ADDRESS_EXPECTED ", expected <host>[:<port>] or [<ipv6>][:<port>]"
#define TIMEOUT_INVALID \
	"Invalid parameter value for `sa-timeout` in `secret-agent` section"
#define PORT_INVALID \
	"Invalid parameter value for `sa-port` in `secret-agent` section"
#define ADDRESS_INVALID \
	"Invalid parameter value for `sa-address` in `secret-agent` section"

#define TOOL_TEST(name) \
static void name(bool backup); \
START_TEST(name ## _backup) \
{ \
	name(true); \
} \
END_TEST \
START_TEST(name ## _restore) \
{ \
	name(false); \
} \
END_TEST \
static void \
name(bool backup)

#define ADD_TOOL_TEST(tc, name) \
	tcase_add_test(tc, name ## _backup); \
	tcase_add_test(tc, name ## _restore)

typedef struct tool_conf_s {
	bool backup;
	backup_config_t bup;
	restore_config_t res;
	sa_cfg* sa;
	char* out;
} tool_conf_t;

typedef struct fake_agent_s {
	int fd;
	char address[32];
	pthread_t thread;
	bool running;
	int stop;
	int connections;
	int requests;
	int tls_hellos;
	const char* reply;
	char request[1024];
} fake_agent_t;

static fake_agent_t g_agents[2];


static void
vwrite_text(const char* path, const char* format, va_list args)
{
	FILE* f = fopen(path, "w");
	ck_assert(f != NULL);
	vfprintf(f, format, args);
	fclose(f);
}

static void
write_text(const char* path, const char* format, ...)
{
	va_list args;
	va_start(args, format);
	vwrite_text(path, format, args);
	va_end(args);
}

static void
write_ca_cert(const char* path)
{
	EVP_PKEY* key = EVP_EC_gen("P-256");
	X509* cert = X509_new();
	ck_assert_ptr_ne(key, NULL);
	ck_assert_ptr_ne(cert, NULL);

	X509_NAME* name = X509_get_subject_name(cert);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
			(const unsigned char*) "127.0.0.1", -1, -1, 0);
	X509_set_issuer_name(cert, name);
	ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
	X509_gmtime_adj(X509_getm_notBefore(cert), 0);
	X509_gmtime_adj(X509_getm_notAfter(cert), 3600);
	X509_set_pubkey(cert, key);
	ck_assert_int_ne(X509_sign(cert, key, EVP_sha256()), 0);

	FILE* f = fopen(path, "w");
	ck_assert(f != NULL);
	ck_assert_int_eq(PEM_write_X509(f, cert), 1);
	fclose(f);

	X509_free(cert);
	EVP_PKEY_free(key);
}

static bool
recv_all(int fd, void* buf, size_t len)
{
	uint8_t* p = (uint8_t*) buf;

	while (len > 0) {
		ssize_t n = recv(fd, p, len, 0);

		if (n <= 0) {
			return false;
		}

		p += n;
		len -= (size_t) n;
	}

	return true;
}

static void
fake_agent_serve(fake_agent_t* agent, int fd)
{
	struct timeval tv = { 1, 0 };
	uint32_t header[2];

	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	if (! recv_all(fd, header, sizeof(header))) {
		return;
	}

	if (*(uint8_t*) header == TLS_HANDSHAKE) {
		__atomic_add_fetch(&agent->tls_hellos, 1, __ATOMIC_SEQ_CST);
		return;
	}

	uint32_t size = ntohl(header[1]);

	if (ntohl(header[0]) != SA_MAGIC || size >= sizeof(agent->request) ||
			! recv_all(fd, agent->request, size)) {
		return;
	}

	agent->request[size] = '\0';
	__atomic_add_fetch(&agent->requests, 1, __ATOMIC_SEQ_CST);

	uint32_t reply_len = (uint32_t) strlen(agent->reply);
	header[0] = htonl(SA_MAGIC);
	header[1] = htonl(reply_len);
	send(fd, header, sizeof(header), 0);
	send(fd, agent->reply, reply_len, 0);
}

static void*
fake_agent_run(void* arg)
{
	fake_agent_t* agent = (fake_agent_t*) arg;

	while (true) {
		bool stopping = __atomic_load_n(&agent->stop, __ATOMIC_SEQ_CST) != 0;
		struct pollfd pfd = { .fd = agent->fd, .events = POLLIN };

		if (poll(&pfd, 1, stopping ? 0 : 10) <= 0) {
			if (stopping) {
				break;
			}

			continue;
		}

		int fd = accept(agent->fd, NULL, NULL);

		if (fd < 0) {
			continue;
		}

		__atomic_add_fetch(&agent->connections, 1, __ATOMIC_SEQ_CST);
		fake_agent_serve(agent, fd);
		close(fd);
	}

	return NULL;
}

static fake_agent_t*
fake_agent_start_replying(fake_agent_t* agent, const char* reply)
{
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);

	memset(agent, 0, sizeof(*agent));
	agent->reply = reply;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	agent->fd = socket(AF_INET, SOCK_STREAM, 0);
	ck_assert_int_ge(agent->fd, 0);
	ck_assert_int_eq(bind(agent->fd, (struct sockaddr*) &addr, sizeof(addr)), 0);
	ck_assert_int_eq(listen(agent->fd, 16), 0);
	ck_assert_int_eq(getsockname(agent->fd, (struct sockaddr*) &addr, &len), 0);
	snprintf(agent->address, sizeof(agent->address), "127.0.0.1:%u",
			ntohs(addr.sin_port));

	ck_assert_int_eq(pthread_create(&agent->thread, NULL, fake_agent_run, agent), 0);
	agent->running = true;
	return agent;
}

static fake_agent_t*
fake_agent_start(fake_agent_t* agent)
{
	return fake_agent_start_replying(agent, SECRET_REPLY);
}

static void
fake_agent_stop(fake_agent_t* agent)
{
	if (! agent->running) {
		return;
	}

	__atomic_store_n(&agent->stop, 1, __ATOMIC_SEQ_CST);
	pthread_join(agent->thread, NULL);
	close(agent->fd);
	agent->running = false;
}

static void
sa_teardown(void)
{
	fake_agent_stop(&g_agents[0]);
	fake_agent_stop(&g_agents[1]);

	remove(CONF_FILE);
	remove(LATER_CONF_FILE);
	remove(INCLUDE_DIR_FILE);
	rmdir(INCLUDE_DIR);
	remove(OUT_FILE);
	remove(CA_CERT_FILE);
}

static char*
read_out(void)
{
	static char buf[64 * 1024];

	FILE* f = fopen(OUT_FILE, "rb");
	ck_assert(f != NULL);
	size_t len = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);
	buf[len] = '\0';
	return buf;
}

static int
tool_set(tool_conf_t* t, bool backup, int argc, char* argv[])
{
	t->backup = backup;
	argv[0] = backup ? "asbackup" : "asrestore";

	fflush(stdout);
	fflush(stderr);
	int saved_stdout = dup(STDOUT_FILENO);
	int saved_stderr = dup(STDERR_FILENO);
	FILE* f = fopen(OUT_FILE, "w");
	ck_assert(f != NULL);
	dup2(fileno(f), STDOUT_FILENO);
	dup2(fileno(f), STDERR_FILENO);
	fclose(f);

	int rc = backup ? backup_config_set(argc, argv, &t->bup) :
			restore_config_set(argc, argv, &t->res);

	fflush(stdout);
	fflush(stderr);
	dup2(saved_stdout, STDOUT_FILENO);
	dup2(saved_stderr, STDERR_FILENO);
	close(saved_stdout);
	close(saved_stderr);

	t->out = read_out();
	t->sa = backup ? &t->bup.secret_cfg : &t->res.secret_cfg;
	return rc;
}

static int
tool_vrun(tool_conf_t* t, bool backup, va_list args)
{
	char* argv[32];
	int argc = 1;

	while (argc < 31 && (argv[argc] = va_arg(args, char*)) != NULL) {
		argc++;
	}

	argv[argc] = NULL;
	return tool_set(t, backup, argc, argv);
}

static int
tool_run(tool_conf_t* t, int backup, ...)
{
	va_list args;
	va_start(args, backup);
	int rc = tool_vrun(t, backup != 0, args);
	va_end(args);
	return rc;
}

static int
conf_run(tool_conf_t* t, bool backup, const char* section)
{
	write_text(CONF_FILE, "[secret-agent]\n%s", section);
	return tool_run(t, backup, "--only-config-file", CONF_FILE, NULL);
}

static void
tool_destroy(tool_conf_t* t)
{
	if (t->backup) {
		backup_config_destroy(&t->bup);
	}
	else {
		restore_config_destroy(&t->res);
	}
}

static const char*
tool_host(tool_conf_t* t)
{
	return t->backup ? t->bup.host : t->res.host;
}

static int
failure(bool backup)
{
	return backup ? BACKUP_CONFIG_INIT_FAILURE : RESTORE_CONFIG_INIT_FAILURE;
}

static int
count_of(const char* text, const char* needle)
{
	int n = 0;

	for (const char* p = strstr(text, needle); p != NULL;
			p = strstr(p + strlen(needle), needle)) {
		n++;
	}

	return n;
}

static bool
has_line(const char* text, const char* a, const char* b)
{
	while (*text != '\0') {
		const char* end = strchr(text, '\n');
		size_t len = end != NULL ? (size_t) (end - text) : strlen(text);
		char line[1024];

		snprintf(line, sizeof(line), "%.*s", (int) len, text);

		if (strstr(line, a) != NULL && strstr(line, b) != NULL) {
			return true;
		}

		text += len + (end != NULL ? 1 : 0);
	}

	return false;
}

static void
assert_ok(tool_conf_t* t, int rc)
{
	ck_assert_msg(rc == 0, "config set returned %d, output: %s", rc, t->out);
}

static void
assert_fails(tool_conf_t* t, int rc, const char* message)
{
	ck_assert_msg(rc == failure(t->backup),
			"config set returned %d, expected a failure with \"%s\", output: %s",
			rc, message, t->out);
	ck_assert_msg(strstr(t->out, message) != NULL, "\"%s\" not in output: %s",
			message, t->out);
}

static void
assert_agent(tool_conf_t* t, const char* host, const char* port)
{
	ck_assert_str_eq(t->sa->addr, host);
	ck_assert_str_eq(t->sa->port, port);
}

static void
assert_ca_file(tool_conf_t* t, const char* path)
{
	char* expected = read_file_as_string(path);
	ck_assert_ptr_ne(expected, NULL);
	ck_assert_ptr_ne(t->sa->tls.ca_string, NULL);
	ck_assert_msg(strcmp(t->sa->tls.ca_string, expected) == 0,
			"CA is not the contents of %s", path);
	ck_assert(t->sa->tls.enabled);
	cf_free(expected);
}

static void
assert_no_ca_file(tool_conf_t* t)
{
	ck_assert_ptr_eq(t->sa->tls.ca_string, NULL);
	ck_assert(! t->sa->tls.enabled);
}

static void
assert_conf_agent(bool backup, const char* section, const char* host,
		const char* port)
{
	tool_conf_t t;
	assert_ok(&t, conf_run(&t, backup, section));
	assert_agent(&t, host, port);
	tool_destroy(&t);
}

static void
assert_cli_agent(bool backup, const char* host, const char* port, ...)
{
	char* argv[32] = { NULL, "--no-config-file" };
	int argc = 2;
	va_list args;

	va_start(args, port);
	while (argc < 31 && (argv[argc] = va_arg(args, char*)) != NULL) {
		argc++;
	}
	va_end(args);
	argv[argc] = NULL;

	tool_conf_t t;
	assert_ok(&t, tool_set(&t, backup, argc, argv));
	assert_agent(&t, host, port);
	tool_destroy(&t);
}

static void
assert_conf_fails(bool backup, const char* section, const char* message)
{
	tool_conf_t t;
	int rc = conf_run(&t, backup, section);
	ck_assert_msg(rc != 0, "config set accepted %s", section);
	assert_fails(&t, rc, message);
	tool_destroy(&t);
}

static void
assert_conf_timeout(bool backup, const char* value, int expected)
{
	char section[64];
	snprintf(section, sizeof(section), "sa-timeout = %s\n", value);

	tool_conf_t t;
	assert_ok(&t, conf_run(&t, backup, section));
	ck_assert_int_eq(t.sa->timeout, expected);
	tool_destroy(&t);
}

static void
assert_conf_timeout_invalid(bool backup, const char* value)
{
	char section[64];
	snprintf(section, sizeof(section), "sa-timeout = %s\n", value);
	assert_conf_fails(backup, section, TIMEOUT_INVALID);
}

static void
assert_cli_timeout(bool backup, char* value, int expected)
{
	tool_conf_t t;
	assert_ok(&t, tool_run(&t, backup, "--no-config-file", "--sa-timeout", value,
			NULL));
	ck_assert_int_eq(t.sa->timeout, expected);
	tool_destroy(&t);
}

static void
assert_cli_invalid(bool backup, char* option, char* value, const char* expected)
{
	char message[160];
	snprintf(message, sizeof(message), "%s: invalid value %s%s", option, value,
			expected);

	tool_conf_t t;
	assert_fails(&t, tool_run(&t, backup, "--no-config-file", option, value,
			NULL), message);
	tool_destroy(&t);
}

static void
assert_cli_timeout_invalid(bool backup, char* value)
{
	assert_cli_invalid(backup, "--sa-timeout", value, TIMEOUT_EXPECTED);
}

static void
assert_cli_port_invalid(bool backup, char* value)
{
	assert_cli_invalid(backup, "--sa-port", value, PORT_EXPECTED);
}

static void
assert_cli_address_invalid(bool backup, char* value)
{
	assert_cli_invalid(backup, "--sa-address", value, ADDRESS_EXPECTED);
}

static char*
help_text(bool backup)
{
	tool_conf_t t;
	int rc = tool_run(&t, backup, "--help", NULL);
	ck_assert_int_eq(rc, backup ? BACKUP_CONFIG_INIT_EXIT : RESTORE_CONFIG_INIT_EXIT);
	tool_destroy(&t);
	return t.out;
}

static const char*
help_block(const char* help, const char* option, char* block, size_t size)
{
	const char* start = strstr(help, option);
	ck_assert_msg(start != NULL, "help has no %s", option);

	const char* end = strstr(start + 1, "\n --");
	int len = end != NULL ? (int) (end - start) : (int) strlen(start);
	snprintf(block, size, "%.*s", len, start);
	return block;
}

static void
assert_request(const char* request, const char* resource, const char* key)
{
	json_error_t error;
	json_t* doc = json_loads(request, JSON_REJECT_DUPLICATES, &error);
	ck_assert_msg(doc != NULL, "request is not valid JSON (%s): %s", error.text,
			request);

	const char* got_resource = NULL;
	const char* got_key = NULL;
	ck_assert_msg(json_unpack(doc, "{s:s, s:s !}", "Resource", &got_resource,
			"SecretKey", &got_key) == 0, "unexpected request: %s", request);
	ck_assert_str_eq(got_resource, resource);
	ck_assert_str_eq(got_key, key);
	json_decref(doc);
}


TOOL_TEST(test_cli_address_port_and_sa_port)
{
	assert_cli_agent(backup, "127.0.0.1", "43005",
			"--sa-address", "127.0.0.1:9999", "--sa-port", "43005", NULL);
}

TOOL_TEST(test_conf_address_port_and_sa_port)
{
	assert_conf_agent(backup, "sa-address = \"127.0.0.1:9999\"\n"
			"sa-port = \"43005\"\n", "127.0.0.1", "43005");
}

TOOL_TEST(test_conf_ipv6_address_with_port)
{
	assert_conf_agent(backup, "sa-address = \"[::1]:43007\"\n", "::1", "43007");
}

TOOL_TEST(test_conf_ipv6_address_without_port)
{
	assert_conf_agent(backup, "sa-address = \"[::1]\"\n", "::1", "3005");
	assert_conf_agent(backup, "sa-address = \"[::1]\"\nsa-port = \"43007\"\n",
			"::1", "43007");
}

TOOL_TEST(test_conf_ipv6_address_unbracketed)
{
	assert_conf_agent(backup, "sa-address = \"::1\"\n", "::1", "3005");
}

TOOL_TEST(test_conf_ipv6_address_port_and_sa_port)
{
	assert_conf_agent(backup, "sa-address = \"[::1]:43007\"\n"
			"sa-port = \"43005\"\n", "::1", "43005");
}

TOOL_TEST(test_cli_ipv6_address_with_port)
{
	assert_cli_agent(backup, "::1", "43007", "--sa-address", "[::1]:43007", NULL);
}

TOOL_TEST(test_cli_ipv6_address_without_port)
{
	assert_cli_agent(backup, "::1", "43007",
			"--sa-address", "[::1]", "--sa-port", "43007", NULL);
	assert_cli_agent(backup, "::1", "3005", "--sa-address", "[::1]", NULL);
}

TOOL_TEST(test_cli_ipv6_address_unbracketed)
{
	assert_cli_agent(backup, "::1", "3005", "--sa-address", "::1", NULL);
}

TOOL_TEST(test_cli_ipv6_address_port_and_sa_port)
{
	assert_cli_agent(backup, "::1", "43005",
			"--sa-address", "[::1]:43007", "--sa-port", "43005", NULL);
}

TOOL_TEST(test_conf_secret_uses_cli_agent)
{
	fake_agent_t* file_agent = fake_agent_start(&g_agents[0]);
	fake_agent_t* cli_agent = fake_agent_start(&g_agents[1]);
	write_text(CONF_FILE, "[cluster]\nhost = \"secrets:r:host\"\n"
			"[secret-agent]\nsa-address = \"%s\"\n", file_agent->address);

	tool_conf_t t;
	int rc = tool_run(&t, backup, "--only-config-file", CONF_FILE,
			"--sa-address", cli_agent->address, NULL);
	fake_agent_stop(file_agent);
	fake_agent_stop(cli_agent);

	ck_assert_int_eq(file_agent->connections, 0);
	ck_assert_int_eq(cli_agent->requests, 1);
	assert_ok(&t, rc);
	ck_assert_str_eq(tool_host(&t), "127.0.0.1");
	tool_destroy(&t);
}

TOOL_TEST(test_conf_secret_uses_cli_ca_file)
{
	write_ca_cert(CA_CERT_FILE);
	fake_agent_t* file_agent = fake_agent_start(&g_agents[0]);
	fake_agent_t* cli_agent = fake_agent_start(&g_agents[1]);
	write_text(CONF_FILE, "[cluster]\nhost = \"secrets:r:host\"\n"
			"[secret-agent]\nsa-address = \"%s\"\n", file_agent->address);

	tool_conf_t t;
	int rc = tool_run(&t, backup, "--only-config-file", CONF_FILE,
			"--sa-address", cli_agent->address, "--sa-ca-file", CA_CERT_FILE, NULL);
	fake_agent_stop(file_agent);
	fake_agent_stop(cli_agent);

	ck_assert_int_eq(file_agent->connections, 0);
	ck_assert_int_eq(cli_agent->tls_hellos, 1);
	ck_assert_int_eq(cli_agent->requests, 0);
	ck_assert_int_eq(rc, failure(backup));
	tool_destroy(&t);
}

TOOL_TEST(test_conf_secret_overridden_by_cli_not_fetched)
{
	fake_agent_t* agent = fake_agent_start(&g_agents[0]);
	write_text(CONF_FILE, "[cluster]\nhost = \"secrets:r:host\"\n"
			"[secret-agent]\nsa-address = \"%s\"\n", agent->address);

	tool_conf_t t;
	int rc = tool_run(&t, backup, "--only-config-file", CONF_FILE,
			"--host", "10.0.0.1", NULL);
	fake_agent_stop(agent);

	ck_assert_int_eq(agent->connections, 0);
	assert_ok(&t, rc);
	ck_assert_str_eq(tool_host(&t), "10.0.0.1");
	tool_destroy(&t);
}

TOOL_TEST(test_unknown_key_fetches_nothing)
{
	fake_agent_t* file_agent = fake_agent_start(&g_agents[0]);
	fake_agent_t* cli_agent = fake_agent_start(&g_agents[1]);
	write_text(CONF_FILE, "[cluster]\nhost = \"secrets:r:host\"\n"
			"[secret-agent]\nsa-address = \"%s\"\nsa-adress = \"127.0.0.1\"\n",
			file_agent->address);

	tool_conf_t t;
	int rc = tool_run(&t, backup, "--only-config-file", CONF_FILE,
			"--sa-address", cli_agent->address, "--user", "secrets:r:user", NULL);
	fake_agent_stop(file_agent);
	fake_agent_stop(cli_agent);

	ck_assert_int_eq(file_agent->connections, 0);
	ck_assert_int_eq(cli_agent->connections, 0);
	assert_fails(&t, rc, "Unknown parameter `sa-adress` in `secret-agent` section");
	tool_destroy(&t);
}

TOOL_TEST(test_wrong_type_fetches_nothing)
{
	fake_agent_t* agent = fake_agent_start(&g_agents[0]);
	write_text(CONF_FILE, "[cluster]\nhost = \"secrets:r:host\"\n"
			"[secret-agent]\nsa-address = \"%s\"\nsa-timeout = true\n",
			agent->address);

	tool_conf_t t;
	int rc = tool_run(&t, backup, "--only-config-file", CONF_FILE, NULL);
	fake_agent_stop(agent);

	ck_assert_int_eq(agent->connections, 0);
	assert_fails(&t, rc, TIMEOUT_INVALID);
	tool_destroy(&t);
}

TOOL_TEST(test_bad_later_file_fetches_nothing)
{
	fake_agent_t* agent = fake_agent_start(&g_agents[0]);
	write_text(CONF_FILE, "[cluster]\nhost = \"secrets:r:host\"\n"
			"[secret-agent]\nsa-address = \"%s\"\n" INCLUDE_LATER, agent->address);
	write_text(LATER_CONF_FILE, "[secret-agent]\nsa-adress = \"127.0.0.1\"\n");

	tool_conf_t t;
	int rc = tool_run(&t, backup, "--only-config-file", CONF_FILE, NULL);
	fake_agent_stop(agent);

	ck_assert_int_eq(agent->connections, 0);
	assert_fails(&t, rc, "Unknown parameter `sa-adress` in `secret-agent` section");
	tool_destroy(&t);
}

TOOL_TEST(test_bad_file_in_include_directory_fetches_nothing)
{
	fake_agent_t* agent = fake_agent_start(&g_agents[0]);
	mkdir(INCLUDE_DIR, 0700);
	write_text(CONF_FILE, "[secret-agent]\nsa-address = \"%s\"\n"
			"[include]\ndirectory = \"" INCLUDE_DIR "\"\n", agent->address);
	write_text(INCLUDE_DIR_FILE, "[cluster]\nuser = \"secrets:r:user\"\n"
			"[secret-agent]\nsa-adress = \"127.0.0.1\"\n");

	tool_conf_t t;
	int rc = tool_run(&t, backup, "--only-config-file", CONF_FILE, NULL);
	fake_agent_stop(agent);

	ck_assert_int_eq(agent->connections, 0);
	assert_fails(&t, rc, "Unknown parameter `sa-adress` in `secret-agent` section");
	tool_destroy(&t);
}

TOOL_TEST(test_secret_path_escaped_in_request)
{
	static const char* const cases[][3] = {
		{ "secrets:a\"b:pw", "a\"b", "pw" },
		{ "secrets:res:p\\w", "res", "p\\w" },
		{ "secrets:nope\",\"Resource\":\"other:pw", "nope\",\"Resource\":\"other",
			"pw" },
	};

	for (uint32_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		fake_agent_t* agent = fake_agent_start_replying(&g_agents[0], ERROR_REPLY);

		tool_conf_t t;
		int rc = tool_run(&t, backup, "--no-config-file", "--sa-address",
				agent->address, "--host", cases[i][0], NULL);
		fake_agent_stop(agent);

		ck_assert_int_eq(agent->connections, 1);
		ck_assert_int_eq(agent->requests, 1);
		assert_request(agent->request, cases[i][1], cases[i][2]);
		assert_fails(&t, rc, AGENT_ERROR);
		tool_destroy(&t);
	}
}

TOOL_TEST(test_cli_sa_port_invalid)
{
	assert_cli_port_invalid(backup, "0");
	assert_cli_port_invalid(backup, "65536");
	assert_cli_port_invalid(backup, "99999");
	assert_cli_port_invalid(backup, "-1");
	assert_cli_port_invalid(backup, "+1");
	assert_cli_port_invalid(backup, "");
	assert_cli_port_invalid(backup, "http");
}

TOOL_TEST(test_conf_sa_port_invalid)
{
	assert_conf_fails(backup, "sa-port = 0\n", PORT_INVALID);
	assert_conf_fails(backup, "sa-port = \"65536\"\n", PORT_INVALID);
	assert_conf_fails(backup, "sa-port = \"http\"\n", PORT_INVALID);
	assert_conf_fails(backup, "sa-port = true\n", PORT_INVALID);
}

TOOL_TEST(test_cli_sa_address_invalid)
{
	assert_cli_address_invalid(backup, "[127.0.0.1]:3005");
	assert_cli_address_invalid(backup, "[::1");
	assert_cli_address_invalid(backup, "");
	assert_cli_address_invalid(backup, "host:");
	assert_cli_address_invalid(backup, "host:abc");
}

TOOL_TEST(test_conf_sa_address_invalid)
{
	assert_conf_fails(backup, "sa-address = \"[127.0.0.1]:3005\"\n",
			ADDRESS_INVALID);
	assert_conf_fails(backup, "sa-address = \"[::1\"\n", ADDRESS_INVALID);
	assert_conf_fails(backup, "sa-address = \"\"\n", ADDRESS_INVALID);
	assert_conf_fails(backup, "sa-address = \"host:\"\n", ADDRESS_INVALID);
	assert_conf_fails(backup, "sa-address = \"host:abc\"\n", ADDRESS_INVALID);
}

TOOL_TEST(test_cli_hostname_address)
{
	assert_cli_agent(backup, "host", "3005", "--sa-address", "host", NULL);
	assert_cli_agent(backup, "host", "43005", "--sa-address", "host:43005", NULL);
}

TOOL_TEST(test_conf_hostname_address)
{
	assert_conf_agent(backup, "sa-address = \"host\"\n", "host", "3005");
	assert_conf_agent(backup, "sa-address = \"host:43005\"\n", "host", "43005");
}

TOOL_TEST(test_help_sa_timeout_range)
{
	char block[1024];
	help_block(help_text(backup), " --sa-timeout=", block, sizeof(block));

	ck_assert_msg(strstr(block, "A value of 0") == NULL,
			"--sa-timeout help still describes 0: %s", block);
	ck_assert_msg(strstr(block,
			"Timeout in milliseconds for Secret Agent requests, an integer\n"
			"                      from 1 to 2147483647.\n"
			"                      Default: 1000") != NULL,
			"--sa-timeout help does not give the range: %s", block);
}

TOOL_TEST(test_help_sa_port_range)
{
	char block[1024];
	help_block(help_text(backup), " --sa-port=", block, sizeof(block));

	ck_assert_msg(strstr(block,
			"Secret Agent port, 1 to 65535. Overrides a port in --sa-address.\n"
			"                      Default: 3005") != NULL,
			"--sa-port help does not give the range: %s", block);
}

TOOL_TEST(test_help_sa_address_ipv6)
{
	char block[1024];
	help_block(help_text(backup), " --sa-address=", block, sizeof(block));

	ck_assert_msg(strstr(block,
			"\"<host>[:<port>]\" or \"[<ipv6>][:<port>]\".\n"
			"                      Secret Agent hostname or IP address.\n"
			"                      Default: 127.0.0.1:3005\n") != NULL,
			"--sa-address help does not list [<ipv6>][:<port>]: %s", block);
}

TOOL_TEST(test_cli_sa_timeout_zero)
{
	assert_cli_timeout_invalid(backup, "0");
}

TOOL_TEST(test_cli_sa_timeout_invalid)
{
	assert_cli_timeout_invalid(backup, "-1");
	assert_cli_timeout_invalid(backup, "2147483648");
	assert_cli_timeout_invalid(backup, "4294968296");
	assert_cli_timeout_invalid(backup, "abc");
	assert_cli_timeout_invalid(backup, "1.5");
	assert_cli_timeout_invalid(backup, "");
}

TOOL_TEST(test_cli_sa_timeout_not_digits)
{
	assert_cli_timeout_invalid(backup, "+5");
	assert_cli_timeout_invalid(backup, " 5");
}

TOOL_TEST(test_cli_sa_timeout_bounds)
{
	assert_cli_timeout(backup, "1", 1);
	assert_cli_timeout(backup, "2147483647", INT_MAX);
}

TOOL_TEST(test_conf_sa_timeout_out_of_range)
{
	assert_conf_timeout_invalid(backup, "0");
	assert_conf_timeout_invalid(backup, "-1");
	assert_conf_timeout_invalid(backup, "2147483648");
	assert_conf_timeout_invalid(backup, "4294968296");
	assert_conf_timeout_invalid(backup, "\"0\"");
	assert_conf_timeout_invalid(backup, "\"2147483648\"");
}

TOOL_TEST(test_conf_sa_timeout_wrong_type)
{
	assert_conf_timeout_invalid(backup, "1.5");
	assert_conf_timeout_invalid(backup, "true");
	assert_conf_timeout_invalid(backup, "\"abc\"");
	assert_conf_timeout_invalid(backup, "\"\"");
	assert_conf_timeout_invalid(backup, "\"-1\"");
	assert_conf_timeout_invalid(backup, "\"+5\"");
	assert_conf_timeout_invalid(backup, "\" 1000\"");
	assert_conf_timeout_invalid(backup, "\"1e3\"");
}

TOOL_TEST(test_conf_sa_timeout_bounds)
{
	assert_conf_timeout(backup, "1", 1);
	assert_conf_timeout(backup, "2147483647", INT_MAX);
}

TOOL_TEST(test_conf_sa_timeout_digit_string)
{
	assert_conf_timeout(backup, "\"2500\"", 2500);
	assert_conf_timeout(backup, "\"2147483647\"", INT_MAX);
}

TOOL_TEST(test_conf_sa_port_integer)
{
	assert_conf_agent(backup, "sa-port = 43005\n", "127.0.0.1", "43005");
}

TOOL_TEST(test_conf_sa_cafile_wrong_type)
{
	assert_conf_fails(backup, "sa-ca-file = \"" CA_FILE "\"\nsa-cafile = 5\n",
			"Invalid parameter value for `sa-cafile` in `secret-agent` section");
	assert_conf_fails(backup, "sa-cafile = 5\nsa-ca-file = \"" CA_FILE "\"\n",
			"Invalid parameter value for `sa-cafile` in `secret-agent` section");
}

TOOL_TEST(test_conf_sa_ca_file_wrong_type)
{
	assert_conf_fails(backup, "sa-ca-file = 5\n",
			"Invalid parameter value for `sa-ca-file` in `secret-agent` section");
	assert_conf_fails(backup, "sa-cafile = \"" CA_FILE "\"\nsa-ca-file = 5\n",
			"Invalid parameter value for `sa-ca-file` in `secret-agent` section");
}

TOOL_TEST(test_cli_sa_cafile_deprecated)
{
	tool_conf_t t;

	assert_ok(&t, tool_run(&t, backup, "--no-config-file", "--sa-cafile", CA_FILE,
			NULL));
	ck_assert_msg(count_of(t.out, SA_CAFILE_DEPRECATED) == 1,
			"expected one deprecation warning, output: %s", t.out);
	assert_ca_file(&t, CA_FILE);
	tool_destroy(&t);

	assert_ok(&t, tool_run(&t, backup, "--no-config-file", "--sa-ca-file", CA_FILE,
			"--sa-cafile", CA_FILE2, NULL));
	ck_assert_msg(count_of(t.out, SA_CAFILE_DEPRECATED) == 1,
			"expected one deprecation warning, output: %s", t.out);
	assert_ca_file(&t, CA_FILE);
	tool_destroy(&t);
}

TOOL_TEST(test_sa_ca_file_not_deprecated)
{
	tool_conf_t t;

	assert_ok(&t, tool_run(&t, backup, "--no-config-file", "--sa-ca-file", CA_FILE,
			NULL));
	ck_assert_msg(strstr(t.out, "deprecated") == NULL, "output: %s", t.out);
	tool_destroy(&t);

	assert_ok(&t, conf_run(&t, backup, "sa-ca-file = \"" CA_FILE "\"\n"));
	ck_assert_msg(strstr(t.out, "deprecated") == NULL, "output: %s", t.out);
	tool_destroy(&t);

	assert_ok(&t, conf_run(&t, backup, "sa-cafile = \"" CA_FILE "\"\n"));
	ck_assert_msg(strstr(t.out, "deprecated") == NULL, "output: %s", t.out);
	tool_destroy(&t);
}

TOOL_TEST(test_help_lists_sa_ca_file_only)
{
	tool_conf_t t;
	int rc = tool_run(&t, backup, "--help", NULL);

	ck_assert_int_eq(rc, backup ? BACKUP_CONFIG_INIT_EXIT : RESTORE_CONFIG_INIT_EXIT);
	ck_assert_ptr_ne(strstr(t.out, " --sa-ca-file="), NULL);
	const char* hit = strstr(t.out, "sa-cafile");
	ck_assert_msg(hit == NULL, "help mentions sa-cafile: %.60s", hit);

	char block[1024];
	help_block(t.out, " --sa-ca-file=", block, sizeof(block));
	ck_assert_msg(strstr(block,
			"Path to a CA certificate file. Enables TLS to the Secret Agent\n"
			"                      and verifies its certificate against this CA. The agent's\n"
			"                      hostname or IP address must be in the certificate.\n"
			"                      Default: none\n") != NULL,
			"--sa-ca-file help does not match: %s", block);
	tool_destroy(&t);
}

TOOL_TEST(test_cli_beats_conf)
{
	tool_conf_t t;

	write_text(CONF_FILE, "[secret-agent]\nsa-address = \"127.0.0.1:1111\"\n"
			"sa-timeout = 5\n");
	assert_ok(&t, tool_run(&t, backup, "--only-config-file", CONF_FILE,
			"--sa-address", "127.0.0.2:2222", "--sa-timeout", "7", NULL));
	assert_agent(&t, "127.0.0.2", "2222");
	ck_assert_int_eq(t.sa->timeout, 7);
	tool_destroy(&t);

	assert_ok(&t, tool_run(&t, backup, "--only-config-file", CONF_FILE,
			"--sa-port", "2222", NULL));
	assert_agent(&t, "127.0.0.1", "2222");
	tool_destroy(&t);

	write_text(CONF_FILE, "[secret-agent]\nsa-port = \"1111\"\n");
	assert_ok(&t, tool_run(&t, backup, "--only-config-file", CONF_FILE,
			"--sa-port", "2222", NULL));
	assert_agent(&t, "127.0.0.1", "2222");
	tool_destroy(&t);

	assert_ok(&t, tool_run(&t, backup, "--only-config-file", CONF_FILE,
			"--sa-address", "127.0.0.2:2222", NULL));
	assert_agent(&t, "127.0.0.2", "2222");
	tool_destroy(&t);
}

TOOL_TEST(test_later_file_beats_earlier)
{
	tool_conf_t t;

	write_text(CONF_FILE, "[secret-agent]\nsa-address = \"127.0.0.1:1111\"\n"
			"sa-timeout = 5\nsa-ca-file = \"" CA_FILE2 "\"\n" INCLUDE_LATER);
	write_text(LATER_CONF_FILE, "[secret-agent]\nsa-address = \"127.0.0.2:2222\"\n"
			"sa-timeout = 7\nsa-cafile = \"" CA_FILE "\"\n");
	assert_ok(&t, tool_run(&t, backup, "--only-config-file", CONF_FILE, NULL));
	assert_agent(&t, "127.0.0.2", "2222");
	ck_assert_int_eq(t.sa->timeout, 7);
	assert_ca_file(&t, CA_FILE);
	tool_destroy(&t);

	write_text(LATER_CONF_FILE, "[secret-agent]\nsa-port = \"2222\"\n");
	assert_ok(&t, tool_run(&t, backup, "--only-config-file", CONF_FILE, NULL));
	assert_agent(&t, "127.0.0.1", "2222");
	assert_ca_file(&t, CA_FILE2);
	tool_destroy(&t);

	write_text(CONF_FILE, "[secret-agent]\nsa-port = \"1111\"\n" INCLUDE_LATER);
	write_text(LATER_CONF_FILE, "[secret-agent]\nsa-address = \"127.0.0.2:2222\"\n");
	assert_ok(&t, tool_run(&t, backup, "--only-config-file", CONF_FILE, NULL));
	assert_agent(&t, "127.0.0.2", "2222");
	tool_destroy(&t);
}

TOOL_TEST(test_instance_section_replaces_default)
{
	tool_conf_t t;

	write_text(CONF_FILE, "[secret-agent]\nsa-address = \"127.0.0.1:1111\"\n"
			"sa-timeout = 5\nsa-ca-file = \"" NO_CA_FILE "\"\n"
			"[secret-agent_x]\nsa-address = \"127.0.0.2:2222\"\n");
	assert_ok(&t, tool_run(&t, backup, "--only-config-file", CONF_FILE,
			"--instance", "x", NULL));
	assert_agent(&t, "127.0.0.2", "2222");
	ck_assert_int_eq(t.sa->timeout, 1000);
	assert_no_ca_file(&t);
	tool_destroy(&t);

	assert_fails(&t, tool_run(&t, backup, "--only-config-file", CONF_FILE,
			"--instance", "y", NULL), "Invalid parameter value for `sa-ca-file`");
	tool_destroy(&t);
}

TOOL_TEST(test_empty_ca_file_path)
{
	tool_conf_t t;

	ck_assert_int_eq(tool_run(&t, backup, "--no-config-file", "--sa-ca-file", "",
			NULL), failure(backup));
	assert_no_ca_file(&t);
	tool_destroy(&t);

	ck_assert_int_eq(tool_run(&t, backup, "--no-config-file", "--sa-cafile", "",
			NULL), failure(backup));
	assert_no_ca_file(&t);
	tool_destroy(&t);

	assert_conf_fails(backup, "sa-ca-file = \"\"\n",
			"Invalid parameter value for `sa-ca-file` in `secret-agent` section");
	assert_conf_fails(backup, "sa-cafile = \"\"\n",
			"Invalid parameter value for `sa-cafile` in `secret-agent` section");
}

TOOL_TEST(test_conf_missing_ca_file_names_key)
{
	assert_conf_fails(backup, "sa-ca-file = \"" NO_CA_FILE "\"\n",
			"Invalid parameter value for `sa-ca-file` in `secret-agent` section");
	assert_conf_fails(backup, "sa-cafile = \"" NO_CA_FILE "\"\n",
			"Invalid parameter value for `sa-cafile` in `secret-agent` section");
}

TOOL_TEST(test_cli_missing_ca_file_names_option)
{
	tool_conf_t t;

	assert_fails(&t, tool_run(&t, backup, "--no-config-file", "--sa-ca-file",
			NO_CA_FILE, NULL), NO_CA_FILE);
	ck_assert_msg(has_line(t.out, "--sa-ca-file", NO_CA_FILE),
			"no line names --sa-ca-file and " NO_CA_FILE ", output: %s", t.out);
	tool_destroy(&t);

	assert_fails(&t, tool_run(&t, backup, "--no-config-file", "--sa-cafile",
			NO_CA_FILE, NULL), NO_CA_FILE);
	ck_assert_msg(has_line(t.out, "--sa-cafile", NO_CA_FILE),
			"no line names --sa-cafile and " NO_CA_FILE ", output: %s", t.out);
	tool_destroy(&t);
}



Suite* secret_agent_suite()
{
	Suite* s;
	TCase* tc;

	s = suite_create("Secret agent options");

	tc = tcase_create("Options");
	tcase_add_checked_fixture(tc, NULL, sa_teardown);

	ADD_TOOL_TEST(tc, test_cli_address_port_and_sa_port);
	ADD_TOOL_TEST(tc, test_conf_address_port_and_sa_port);
	ADD_TOOL_TEST(tc, test_conf_ipv6_address_with_port);
	ADD_TOOL_TEST(tc, test_conf_ipv6_address_without_port);
	ADD_TOOL_TEST(tc, test_conf_ipv6_address_unbracketed);
	ADD_TOOL_TEST(tc, test_conf_ipv6_address_port_and_sa_port);
	ADD_TOOL_TEST(tc, test_cli_ipv6_address_with_port);
	ADD_TOOL_TEST(tc, test_cli_ipv6_address_without_port);
	ADD_TOOL_TEST(tc, test_cli_ipv6_address_unbracketed);
	ADD_TOOL_TEST(tc, test_cli_ipv6_address_port_and_sa_port);

	ADD_TOOL_TEST(tc, test_conf_secret_uses_cli_agent);
	ADD_TOOL_TEST(tc, test_conf_secret_uses_cli_ca_file);
	ADD_TOOL_TEST(tc, test_conf_secret_overridden_by_cli_not_fetched);
	ADD_TOOL_TEST(tc, test_unknown_key_fetches_nothing);
	ADD_TOOL_TEST(tc, test_wrong_type_fetches_nothing);
	ADD_TOOL_TEST(tc, test_bad_later_file_fetches_nothing);
	ADD_TOOL_TEST(tc, test_bad_file_in_include_directory_fetches_nothing);
	ADD_TOOL_TEST(tc, test_secret_path_escaped_in_request);

	ADD_TOOL_TEST(tc, test_cli_sa_port_invalid);
	ADD_TOOL_TEST(tc, test_conf_sa_port_invalid);
	ADD_TOOL_TEST(tc, test_cli_sa_address_invalid);
	ADD_TOOL_TEST(tc, test_conf_sa_address_invalid);
	ADD_TOOL_TEST(tc, test_cli_hostname_address);
	ADD_TOOL_TEST(tc, test_conf_hostname_address);
	ADD_TOOL_TEST(tc, test_help_sa_timeout_range);
	ADD_TOOL_TEST(tc, test_help_sa_port_range);
	ADD_TOOL_TEST(tc, test_help_sa_address_ipv6);

	ADD_TOOL_TEST(tc, test_cli_sa_timeout_zero);
	ADD_TOOL_TEST(tc, test_cli_sa_timeout_invalid);
	ADD_TOOL_TEST(tc, test_cli_sa_timeout_not_digits);
	ADD_TOOL_TEST(tc, test_cli_sa_timeout_bounds);
	ADD_TOOL_TEST(tc, test_conf_sa_timeout_out_of_range);
	ADD_TOOL_TEST(tc, test_conf_sa_timeout_wrong_type);
	ADD_TOOL_TEST(tc, test_conf_sa_timeout_bounds);
	ADD_TOOL_TEST(tc, test_conf_sa_timeout_digit_string);
	ADD_TOOL_TEST(tc, test_conf_sa_port_integer);

	ADD_TOOL_TEST(tc, test_conf_sa_cafile_wrong_type);
	ADD_TOOL_TEST(tc, test_conf_sa_ca_file_wrong_type);
	ADD_TOOL_TEST(tc, test_cli_sa_cafile_deprecated);
	ADD_TOOL_TEST(tc, test_sa_ca_file_not_deprecated);
	ADD_TOOL_TEST(tc, test_help_lists_sa_ca_file_only);

	ADD_TOOL_TEST(tc, test_cli_beats_conf);
	ADD_TOOL_TEST(tc, test_later_file_beats_earlier);
	ADD_TOOL_TEST(tc, test_instance_section_replaces_default);
	ADD_TOOL_TEST(tc, test_empty_ca_file_path);
	ADD_TOOL_TEST(tc, test_conf_missing_ca_file_names_key);
	ADD_TOOL_TEST(tc, test_cli_missing_ca_file_names_option);

	suite_add_tcase(s, tc);

	return s;
}
