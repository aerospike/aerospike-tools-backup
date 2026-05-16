/*
 * Aerospike S3 proxy env-var helpers
 *
 * Copyright (c) 2026 Aerospike, Inc. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	S3_PROXY_PARSE_OK = 0,
	S3_PROXY_PARSE_EMPTY = -1,
	S3_PROXY_PARSE_MALFORMED = -2,
	S3_PROXY_PARSE_UNSUPPORTED = -3,
} s3_proxy_parse_status_t;

typedef enum {
	S3_PROXY_SCHEME_HTTP = 0,
	S3_PROXY_SCHEME_HTTPS = 1,
} s3_proxy_scheme_t;

#define S3_PROXY_HOST_MAX 256
#define S3_PROXY_USER_MAX 256
#define S3_PROXY_PASS_MAX 256

typedef struct {
	char host[S3_PROXY_HOST_MAX];
	uint16_t port;
	s3_proxy_scheme_t scheme;
	char username[S3_PROXY_USER_MAX];
	char password[S3_PROXY_PASS_MAX];
} s3_proxy_url_t;

/*
 * Parses a proxy URL of the form:
 *   [scheme://][user[:password]@]host[:port][/...]
 *
 * - scheme is case-insensitive; only http and https are accepted. SOCKS schemes
 *   (socks, socks4, socks4a, socks5, socks5h) return S3_PROXY_PARSE_UNSUPPORTED
 *   because the AWS SDK's CurlHttpClient only emits HTTP/HTTPS proxies.
 * - if scheme is absent, defaults to http.
 * - IPv6 hosts must be bracketed: [::1] or [::1]:8080. Brackets are stripped
 *   from out->host.
 * - if port is absent, defaults to 80 (http) or 443 (https).
 * - userinfo is percent-decoded before being copied to out->username/password.
 * - empty or NULL url returns S3_PROXY_PARSE_EMPTY.
 * - anything else structurally wrong returns S3_PROXY_PARSE_MALFORMED.
 *
 * On any non-OK return, *out is zeroed.
 */
s3_proxy_parse_status_t s3_proxy_parse_url(const char* url,
		s3_proxy_url_t* out);

/*
 * Returns the first non-empty value among the conventional proxy URL env vars
 * for the given destination scheme, or NULL if none are set.
 *
 * Lookup order:
 *   HTTPS dest: https_proxy, HTTPS_PROXY, all_proxy, ALL_PROXY
 *   HTTP  dest: http_proxy,  all_proxy,   ALL_PROXY
 *
 * Uppercase HTTP_PROXY is intentionally not consulted: this mirrors the libcurl
 * and wget convention introduced after CVE-2016-5385 ("httpoxy"), where the
 * uppercase form is reserved for CGI use.
 *
 * The returned pointer is owned by the environment block and must not be freed.
 * It is only valid until the next setenv()/unsetenv()/putenv() on any of the
 * names this function consults; copy the value if you need to outlive that.
 */
const char* s3_proxy_pick_url_env(s3_proxy_scheme_t dest_scheme);

/*
 * Returns the first non-empty value of no_proxy / NO_PROXY (in that order), or
 * NULL if neither is set. Lowercase preferred to match libcurl/wget convention.
 *
 * Same lifetime caveat as s3_proxy_pick_url_env: the returned pointer is owned
 * by the environment block and is only valid until the next setenv/unsetenv on
 * either name.
 */
const char* s3_proxy_pick_no_proxy_env(void);

/*
 * Returns the scheme implied by an S3 endpoint override string, used to keep
 * Aws::ClientConfiguration::scheme in sync with --s3-endpoint-override and to
 * select the right proxy env-var family.
 *
 *   - "https://..." (case-insensitive)         -> S3_PROXY_SCHEME_HTTPS
 *   - "http://..."  (case-insensitive)         -> S3_PROXY_SCHEME_HTTP
 *   - anything else (bare host:port, NULL, "") -> S3_PROXY_SCHEME_HTTP (default)
 *
 * The AWS SDK already uses the scheme prefix from the override URL when
 * constructing request URLs (see BuiltInParameters.cpp in aws-sdk-cpp 1.10.55);
 * this helper exists so the rest of the asbackup code can stay in sync.
 */
s3_proxy_scheme_t s3_proxy_scheme_for_endpoint(const char* endpoint);

#ifdef __cplusplus
}
#endif
