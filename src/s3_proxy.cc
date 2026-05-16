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

#include <s3_proxy.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <string>

namespace {

const char*
read_first_env(std::initializer_list<const char*> names)
{
	for (const char* name : names) {
		const char* val = std::getenv(name);
		if (val != nullptr && val[0] != '\0') {
			return val;
		}
	}
	return nullptr;
}

bool
copy_to_buf(const std::string& src, char* dst, size_t dst_sz)
{
	if (src.size() >= dst_sz) {
		return false;
	}
	std::memcpy(dst, src.data(), src.size());
	dst[src.size()] = '\0';
	return true;
}

int
hex_value(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

bool
percent_decode(const std::string& src, std::string& dst)
{
	dst.clear();
	dst.reserve(src.size());
	for (size_t i = 0; i < src.size(); ++i) {
		if (src[i] == '%') {
			if (i + 2 >= src.size()) {
				return false;
			}
			int hi = hex_value(src[i + 1]);
			int lo = hex_value(src[i + 2]);
			if (hi < 0 || lo < 0) {
				return false;
			}
			dst.push_back(static_cast<char>((hi << 4) | lo));
			i += 2;
		} else {
			dst.push_back(src[i]);
		}
	}
	return true;
}

std::string
lowercase(std::string s)
{
	std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
		return static_cast<char>(std::tolower(c));
	});
	return s;
}

} // namespace


extern "C" const char*
s3_proxy_pick_url_env(s3_proxy_scheme_t dest_scheme)
{
	if (dest_scheme == S3_PROXY_SCHEME_HTTPS) {
		return read_first_env({"https_proxy", "HTTPS_PROXY",
				"all_proxy", "ALL_PROXY"});
	}
	return read_first_env({"http_proxy", "all_proxy", "ALL_PROXY"});
}

extern "C" const char*
s3_proxy_pick_no_proxy_env(void)
{
	return read_first_env({"no_proxy", "NO_PROXY"});
}

extern "C" s3_proxy_parse_status_t
s3_proxy_parse_url(const char* url, s3_proxy_url_t* out)
{
	if (out == nullptr) {
		return S3_PROXY_PARSE_EMPTY;
	}
	std::memset(out, 0, sizeof(*out));

	if (url == nullptr || url[0] == '\0') {
		return S3_PROXY_PARSE_EMPTY;
	}

	std::string u(url);

	bool is_https = false;
	size_t host_start = 0;
	size_t scheme_end = u.find("://");
	if (scheme_end != std::string::npos) {
		std::string scheme = lowercase(u.substr(0, scheme_end));
		if (scheme == "http") {
			is_https = false;
		} else if (scheme == "https") {
			is_https = true;
		} else if (scheme == "socks" || scheme == "socks4" ||
				scheme == "socks4a" || scheme == "socks5" ||
				scheme == "socks5h") {
			std::memset(out, 0, sizeof(*out));
			return S3_PROXY_PARSE_UNSUPPORTED;
		} else {
			std::memset(out, 0, sizeof(*out));
			return S3_PROXY_PARSE_MALFORMED;
		}
		host_start = scheme_end + 3;
	}
	out->scheme = is_https ? S3_PROXY_SCHEME_HTTPS : S3_PROXY_SCHEME_HTTP;

	std::string authority = u.substr(host_start);
	if (authority.empty()) {
		std::memset(out, 0, sizeof(*out));
		return S3_PROXY_PARSE_MALFORMED;
	}

	// Strip any path/query/fragment from the right.
	size_t path_pos = authority.find_first_of("/?#");
	if (path_pos != std::string::npos) {
		authority.resize(path_pos);
	}
	if (authority.empty()) {
		std::memset(out, 0, sizeof(*out));
		return S3_PROXY_PARSE_MALFORMED;
	}

	// Split off userinfo. Per RFC 3986 '@' inside userinfo must be
	// percent-encoded, so the literal '@' is unambiguously the terminator.
	size_t at = authority.rfind('@');
	if (at != std::string::npos) {
		std::string userinfo = authority.substr(0, at);
		authority = authority.substr(at + 1);

		size_t sep = userinfo.find(':');
		std::string raw_user = (sep == std::string::npos)
				? userinfo : userinfo.substr(0, sep);
		std::string raw_pass = (sep == std::string::npos)
				? std::string() : userinfo.substr(sep + 1);

		std::string decoded_user;
		std::string decoded_pass;
		if (!percent_decode(raw_user, decoded_user) ||
				!percent_decode(raw_pass, decoded_pass)) {
			std::memset(out, 0, sizeof(*out));
			return S3_PROXY_PARSE_MALFORMED;
		}
		if (!copy_to_buf(decoded_user, out->username, sizeof(out->username)) ||
				!copy_to_buf(decoded_pass, out->password,
						sizeof(out->password))) {
			std::memset(out, 0, sizeof(*out));
			return S3_PROXY_PARSE_MALFORMED;
		}
	}

	if (authority.empty()) {
		std::memset(out, 0, sizeof(*out));
		return S3_PROXY_PARSE_MALFORMED;
	}

	std::string host;
	std::string port_str;

	if (authority[0] == '[') {
		size_t close = authority.find(']');
		if (close == std::string::npos || close == 1) {
			std::memset(out, 0, sizeof(*out));
			return S3_PROXY_PARSE_MALFORMED;
		}
		host = authority.substr(1, close - 1);
		if (close + 1 < authority.size()) {
			if (authority[close + 1] != ':') {
				std::memset(out, 0, sizeof(*out));
				return S3_PROXY_PARSE_MALFORMED;
			}
			port_str = authority.substr(close + 2);
		}
	} else {
		size_t colon = authority.rfind(':');
		if (colon != std::string::npos) {
			host = authority.substr(0, colon);
			port_str = authority.substr(colon + 1);
		} else {
			host = authority;
		}
	}

	if (host.empty()) {
		std::memset(out, 0, sizeof(*out));
		return S3_PROXY_PARSE_MALFORMED;
	}
	if (!copy_to_buf(host, out->host, sizeof(out->host))) {
		std::memset(out, 0, sizeof(*out));
		return S3_PROXY_PARSE_MALFORMED;
	}

	unsigned long port_val;
	if (port_str.empty()) {
		port_val = is_https ? 443UL : 80UL;
	} else {
		char* end = nullptr;
		port_val = std::strtoul(port_str.c_str(), &end, 10);
		if (end == port_str.c_str() || *end != '\0' ||
				port_val == 0 || port_val > 65535) {
			std::memset(out, 0, sizeof(*out));
			return S3_PROXY_PARSE_MALFORMED;
		}
	}
	out->port = static_cast<uint16_t>(port_val);

	return S3_PROXY_PARSE_OK;
}
