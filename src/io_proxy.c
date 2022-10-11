/*
 * Copyright 2021-2022 Aerospike, Inc.
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

#include <io_proxy.h>

#include <math.h>

#ifdef __APPLE__
#include <machine/endian.h>
#else
#include <endian.h>
#endif /* __APPLE__ */

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/modes.h>

#include <aerospike/as_random.h>

#include <utils.h>


//==========================================================
// Forward Declarations.
//

static int _proxy_init(io_proxy_t* io, uint8_t options);
static void _proxy_free(io_proxy_t* io);
static void _io_proxy_set_error(io_proxy_t* io);
static void _consumer_buffer_init(consumer_buffer_t* cb, uint64_t size);
static void _consumer_buffer_free(consumer_buffer_t* cb);
static void __zero_if_eq(uint64_t* pos, uint64_t* data_pos);
static int _consumer_buffer_serialize(const consumer_buffer_t* cb,
		file_proxy_t* dst);
static int _consumer_buffer_deserialize(consumer_buffer_t* cb,
		file_proxy_t* src);
static void _consumer_buffer_write(consumer_buffer_t* cb, const void** src,
		uint64_t *n_bytes);
static void _consumer_buffer_putc(consumer_buffer_t* cb, char c);
static void _consumer_buffer_read(consumer_buffer_t* cb, void** dst,
		uint64_t *n_bytes);
static int32_t _consumer_buffer_getc(consumer_buffer_t* cb);
static int32_t _consumer_buffer_peekc(consumer_buffer_t* cb);
static int _consumer_buffer_fread(consumer_buffer_t* cb, file_proxy_t* file);
static int64_t _consumer_buffer_fwrite(consumer_buffer_t* cb,
		file_proxy_t* file);
static int64_t _consumer_buffer_compress(io_proxy_t* io, consumer_buffer_t* dst,
		consumer_buffer_t* src, ZSTD_EndDirective z_ed);
static int _consumer_buffer_decompress(io_proxy_t* io, consumer_buffer_t* dst,
		consumer_buffer_t* src);
static int _comp_buffer_end_block(io_proxy_t* io);
static int _consumer_buffer_encrypt(io_proxy_t* io, consumer_buffer_t* dst,
		consumer_buffer_t* src);
static void _consumer_buffer_decrypt(io_proxy_t* io, consumer_buffer_t* dst,
		consumer_buffer_t* src);
static __attribute__((pure)) uint64_t _get_pkey_digest_len(uint8_t flags);
static __attribute__((pure)) bool _at_eof(io_proxy_t* io);
static __attribute__((pure)) uint64_t _calc_output_buffer_len(
		const io_proxy_t* io);
static __attribute__((pure)) uint64_t _calc_input_buffer_len(
		const io_proxy_t* io);
static void _gen_iv(uint8_t iv[AES_BLOCK_SIZE]);
static void _ctr128_add_to(uint8_t dst[AES_BLOCK_SIZE],
		const uint8_t src[AES_BLOCK_SIZE], uint64_t val);
static void _ctr128_sub_from(uint8_t dst[AES_BLOCK_SIZE],
		const uint8_t src[AES_BLOCK_SIZE], uint64_t val);
static int _init_fn(io_write_proxy_t* io);
static int _commit_write(io_write_proxy_t* io, ZSTD_EndDirective z_ed);
static int _buffer_read_block(io_write_proxy_t* io);


//==========================================================
// Public API.
//

void
encryption_key_init(encryption_key_t* key, uint8_t* pkey_data, uint64_t len)
{
	key->data = pkey_data;
	key->len = len;
}

void
encryption_key_clone(encryption_key_t* dst, const encryption_key_t* src)
{
	dst->data = cf_malloc(src->len);
	dst->len = src->len;

	if (src->len > 0) {
		memcpy(dst->data, src->data, src->len);
	}
}

int
io_proxy_read_private_key_file(const char* pkey_file_path,
		encryption_key_t* pkey_buf)
{
	FILE* pkey_file;
	EVP_PKEY* pkey;

	pkey_file = fopen(pkey_file_path, "r");
	if (pkey_file == NULL) {
		err("Could not open private key file \"%s\"",
				pkey_file_path);
		return -1;
	}

	// read the private key into the OpenSSL EVP_PKEY struct
	pkey = PEM_read_PrivateKey(pkey_file, NULL, NULL, NULL);
	fclose(pkey_file);
	if (pkey == NULL) {
		err("Unable to parse private key, make sure the key is in PEM format");
		return -1;
	}

	pkey_buf->data = NULL;
	// encode the key into a temporary buffer
	pkey_buf->len = (uint64_t) i2d_PrivateKey(pkey, &pkey_buf->data);

	EVP_PKEY_free(pkey);
	if (((int64_t) pkey_buf->len) <= 0) {
		err("OpenSSL error: %s", ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}
	return 0;
}

void
encryption_key_free(encryption_key_t* key)
{
	if (key->data != NULL) {
		cf_free(key->data);
		key->data = NULL;
	}
}

int
io_write_proxy_init(io_write_proxy_t* io, const char* file_path,
		uint64_t max_file_size)
{
	if (file_proxy_write_init(&io->file, file_path, max_file_size) != 0) {
		return -1;
	}

	return _proxy_init(io, IO_WRITE_PROXY);
}

int
io_read_proxy_init(io_write_proxy_t* io, const char* file_path)
{
	if (file_proxy_read_init(&io->file, file_path) != 0) {
		return -1;
	}

	return _proxy_init(io, IO_READ_PROXY);
}

int
io_proxy_initialize(io_write_proxy_t* io)
{
	return _init_fn((io_write_proxy_t*) io);
}

int
io_proxy_serialize(io_proxy_t* io, file_proxy_t* file)
{
	if (_init_fn((io_write_proxy_t*) io) != 0) {
		return -1;
	}

	io_proxy_serial_t data = {
		.byte_cnt = htobe64(io->byte_cnt),
		.raw_byte_cnt = htobe64(io->raw_byte_cnt),
		.num = htobe32(io->num),
		.flags = io->flags
	};

	if (io_proxy_do_encrypt(io)) {
		// serialize IV - 1 (i.e. ecount_buf decrypted)
		_ctr128_sub_from(data.iv, io->iv, 1);
	}
	else {
		memset(data.iv, 0, AES_BLOCK_SIZE);
	}

	if (file_proxy_write(file, &data, sizeof(io_proxy_serial_t)) != sizeof(io_proxy_serial_t)) {
		err("Writing serialized io_proxy to file failed");
		return -1;
	}

	if (_consumer_buffer_serialize(&io->buffer, file) != 0) {
		return -1;
	}

	if (io_proxy_do_compress(io) && (_comp_buffer_end_block(io) != 0 ||
				_consumer_buffer_serialize(&io->comp_buffer, file) != 0)) {
		return -1;
	}

	if (io_proxy_do_encrypt(io) && _consumer_buffer_serialize(&io->encrypt_buffer,
				file) != 0) {
		return -1;
	}

	if (file_proxy_serialize(&io->file, file) != 0) {
		return -1;
	}

	return 0;
}

int
io_proxy_deserialize(io_proxy_t* io, file_proxy_t* src)
{
	io_proxy_serial_t data;

	if (file_proxy_read(src, &data, sizeof(io_proxy_serial_t)) != sizeof(io_proxy_serial_t)) {
		err("Reading serialized io_proxy from file failed");
		return -1;
	}

	if (_consumer_buffer_deserialize(&io->buffer, src) != 0) {
		return -1;
	}

	if (((data.flags & IO_PROXY_COMPRESS_MASK) != IO_PROXY_COMPRESS_NONE) &&
			_consumer_buffer_deserialize(&io->comp_buffer, src) != 0) {
		return -1;
	}

	if (((data.flags & IO_PROXY_ENCRYPT_MASK) != IO_PROXY_ENCRYPT_NONE) &&
			_consumer_buffer_deserialize(&io->encrypt_buffer, src) != 0) {
		return -1;
	}

	if (file_proxy_deserialize(&io->file, src) != 0) {
		return -1;
	}

	io->byte_cnt = be64toh(data.byte_cnt);
	io->raw_byte_cnt = be64toh(data.raw_byte_cnt);
	io->num = be32toh(data.num);
	io->flags = (uint8_t) (((uint32_t) IO_PROXY_DESERIALIZE) |
			(data.flags & IO_PROXY_TYPE_MASK));
	io->deserialized_flags = data.flags & IO_PROXY_INIT_FLAGS;
	io->initialized = 0;

	if (data.flags & IO_PROXY_ENCRYPT_MASK) {
		// copy the IV into the iv field of the io_proxy
		memcpy(io->iv, data.iv, AES_BLOCK_SIZE);
	}

	return 0;
}

int
io_proxy_init_encryption(io_proxy_t* io, const encryption_key_t* pkey,
		encryption_opt encrypt_mode)
{
	const uint64_t digest_len = 32;
	EVP_MD_CTX* ctx;
	uint8_t* pkey_digest;
	uint64_t pkey_digest_len;
	uint32_t d_len;

	if (encrypt_mode == IO_PROXY_ENCRYPT_NONE) {
		return 0;
	}

	// hash the encoded key with SHA256
	ctx = EVP_MD_CTX_create();
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 0) {
		EVP_MD_CTX_destroy(ctx);
		err("EVP_DigestInit_ex() failed");
		return -1;
	}

	if (EVP_DigestUpdate(ctx, pkey->data, pkey->len) == 0) {
		EVP_MD_CTX_destroy(ctx);
		err("EVP_DigestUpdate() failed");
		return -1;
	}

	pkey_digest_len = _get_pkey_digest_len((uint8_t) encrypt_mode);
	// since we are using SHA-256, the digest should be 32 bytes
	pkey_digest = (uint8_t*) cf_malloc(digest_len);

	if (EVP_DigestFinal_ex(ctx, pkey_digest, &d_len) == 0 ||
			d_len > digest_len) {
		EVP_MD_CTX_destroy(ctx);
		err("EVP_DigestFinal_ex() failed");
		return -1;
	}
	EVP_MD_CTX_destroy(ctx);

	int res = AES_set_encrypt_key(pkey_digest, (int) (pkey_digest_len * 8),
			&io->pkey_digest);
	if (res < 0) {
		err("Failed to initialize encryption key");
		return -1;
	}

	// we will need to use decryption when reading
	if (io_proxy_is_reader(io)) {
		res = AES_set_decrypt_key(pkey_digest, (int) (pkey_digest_len * 8),
				&io->decrypt_pkey_digest);
		if (res < 0) {
			err("Failed to initialize decryption key");
			return -1;
		}
	}

	memset(pkey_digest, 0, digest_len);
	cf_free(pkey_digest);

	io->flags |= (uint8_t) encrypt_mode;
	return 0;
}

int
io_proxy_init_encryption_file(io_proxy_t* io, const char* pkey_file_path,
		encryption_opt encrypt_mode)
{
	encryption_key_t pkey;
	int res;

	if (encrypt_mode == IO_PROXY_ENCRYPT_NONE) {
		return 0;
	}

	res = io_proxy_read_private_key_file(pkey_file_path, &pkey);
	if (res < 0) {
		return res;
	}

	res = io_proxy_init_encryption(io, &pkey, encrypt_mode);

	encryption_key_free(&pkey);

	return res;
}

int
io_proxy_init_compression(io_proxy_t* io, compression_opt compress_mode)
{
	if (compress_mode == IO_PROXY_COMPRESS_NONE) {
		// do nothing if compression isn't enabled (this isn't an error)
		return 0;
	}

	if (io_proxy_is_writer(io)) {
		io->cctx = ZSTD_createCCtx();
	}
	else {
		io->dctx = ZSTD_createDCtx();
	}
	io->flags |= (uint8_t) compress_mode;

	return 0;
}

int
io_proxy_set_compression_level(io_proxy_t* io, int32_t compression_level)
{
	ZSTD_bounds comp_lvl_bounds;

	if (!io_proxy_is_writer(io)) {
		err("Can only set compression level on a write proxy");
		return -1;
	}
	if (!io_proxy_do_compress(io)) {
		err("Cannot set compression level without enabling compression");
		return -1;
	}

	comp_lvl_bounds = ZSTD_cParam_getBounds(ZSTD_c_compressionLevel);
	if (ZSTD_isError(comp_lvl_bounds.error)) {
		err("Failed to get zstd compression level bounds: %s",
				ZSTD_getErrorName(comp_lvl_bounds.error));
		return -1;
	}

	if (compression_level < comp_lvl_bounds.lowerBound ||
			compression_level > comp_lvl_bounds.upperBound) {
		err("Compression level %" PRId32 " is outside zstd compression level "
				"bounds (%d - %d)",
				compression_level,
				comp_lvl_bounds.lowerBound, comp_lvl_bounds.upperBound);
		return -1;
	}

	size_t res = ZSTD_CCtx_setParameter(io->cctx, ZSTD_c_compressionLevel,
			compression_level);
	if (ZSTD_isError(res)) {
		err("Failed to set compression level: %s", ZSTD_getErrorName(res));
		return -1;
	}

	return 0;
}

int
io_proxy_close(io_proxy_t* io)
{
	if (file_proxy_close(&io->file) != 0) {
		return -1;
	}
	_proxy_free(io);
	return 0;
}

int
io_proxy_close2(io_proxy_t* io, uint8_t mode)
{
	if (file_proxy_close2(&io->file, mode) != 0) {
		return -1;
	}
	_proxy_free(io);
	return 0;
}

__attribute__((pure)) bool
io_proxy_is_writer(io_proxy_t* io)
{
	return (io->flags & IO_PROXY_TYPE_MASK) == IO_WRITE_PROXY;
}

__attribute__((pure)) bool
io_proxy_is_reader(io_proxy_t* io)
{
	return (io->flags & IO_PROXY_TYPE_MASK) == IO_READ_PROXY;
}

__attribute__((pure)) bool
io_proxy_do_compress(const io_proxy_t* io)
{
	return (io->flags & IO_PROXY_COMPRESS_MASK) != 0;
}

__attribute__((pure)) bool
io_proxy_do_encrypt(const io_proxy_t* io)
{
	return (io->flags & IO_PROXY_ENCRYPT_MASK) != 0;
}

const char*
io_proxy_file_path(const io_proxy_t* io)
{
	return file_proxy_path(&io->file);
}

int
parse_compression_type(const char* comp_str, compression_opt* opt)
{
	if (strcmp(comp_str, "zstd") == 0) {
		*opt = IO_PROXY_COMPRESS_ZSTD;
	}
	else {
		// unknown compression type
		return -1;
	}
	return 0;
}

int
parse_encryption_type(const char* enc_str, encryption_opt* opt)
{
	if (strcmp(enc_str, "aes128") == 0) {
		*opt = IO_PROXY_ENCRYPT_AES128;
	}
	else if (strcmp(enc_str, "aes256") == 0) {
		*opt = IO_PROXY_ENCRYPT_AES256;
	}
	else {
		// unknown compression type
		return -1;
	}
	return 0;
}

int64_t
io_write_proxy_bytes_written(const io_write_proxy_t* io)
{
	if (_init_fn((io_write_proxy_t*) io) != 0) {
		return -1;
	}

	if (io->buffer.src == NULL) {
		int64_t res = file_proxy_tellg(&io->file);
		return res;
	}
	else {
		return (int64_t) io->byte_cnt;
	}
}

int64_t
io_write_proxy_absolute_pos(const io_write_proxy_t* io)
{
	if (_init_fn((io_write_proxy_t*) io) != 0) {
		return -1;
	}

	if (io->buffer.src == NULL) {
		int64_t res = file_proxy_tellg(&io->file);
		return res;
	}
	else {
		return (int64_t) (io->raw_byte_cnt + (io->buffer.pos - io->buffer.data_pos));
	}
}

int64_t
io_read_proxy_estimate_pos(const io_read_proxy_t* io)
{
	if (_init_fn((io_write_proxy_t*) io) != 0) {
		return -1;
	}

	if (io->buffer.src == NULL) {
		return file_proxy_tellg(&io->file);
	}
	else {
		// queued_bytes is the total number of (potentially) compressed bytes of
		// data read from the file sitting in intermediate buffers
		uint64_t queued_bytes = 0;
		if (io_proxy_do_compress(io)) {
			queued_bytes += io->decomp_buffer.pos - io->decomp_buffer.data_pos;
		}
		if (io_proxy_do_encrypt(io)) {
			queued_bytes += io->decrypt_buffer.pos - io->decrypt_buffer.data_pos;
		}

		// buffer_fraction_parsed is the fraction of inflated bytes left in buffer
		// that has not been parsed yet
		double buffer_fraction_parsed;
		if (io->buffer.pos == 0) {
			buffer_fraction_parsed = 1;
		}
		else {
			buffer_fraction_parsed =
				(double) io->buffer.data_pos / (double) io->buffer.pos;
		}

		// total_in_buffers is the total number of bytes that have been read from
		// the file and are sitting in one of the buffers
		uint64_t total_in_buffers = io->byte_cnt - io->parsed_byte_cnt;

		// an estimate of the number of bytes that were decompressed into the data
		// that has already been parsed
		uint64_t inflated_estimate = (uint64_t)
			nearbyintl((double) (total_in_buffers - queued_bytes) *
					buffer_fraction_parsed);

		return (int64_t) (io->parsed_byte_cnt + inflated_estimate);
	}
}

ssize_t
io_proxy_write(io_write_proxy_t* io, const void* buf, size_t n_bytes)
{
	uint64_t init_n_bytes = n_bytes;

	if (_init_fn(io) != 0) {
		return -1;
	}

	if (UNLIKELY(!io_proxy_is_writer(io))) {
		err("Can only write from a write proxy");
		return -1;
	}

	if (io->buffer.src == NULL) {
		return (ssize_t) file_proxy_write(&io->file, buf, n_bytes);
	}

	while (n_bytes > 0) {
		_consumer_buffer_write(&io->buffer, &buf, (uint64_t*) &n_bytes);
		if (io->buffer.pos < io->buffer.size) {
			break;
		}
		if (_commit_write(io, ZSTD_e_continue) != 0) {
			break;
		}
	}

	return (ssize_t) (init_n_bytes - n_bytes);
}

int32_t
io_proxy_putc(io_write_proxy_t* io, char c)
{
	if (_init_fn(io) != 0) {
		return -1;
	}

	if (UNLIKELY(!io_proxy_is_writer(io))) {
		err("Can only write from a write proxy");
		return -1;
	}

	if (io->buffer.src == NULL) {
		return (int32_t) file_proxy_putc(&io->file, c);
	}

	_consumer_buffer_putc(&io->buffer, c);
	if (io->buffer.pos == io->buffer.size) {
		if (_commit_write(io, ZSTD_e_continue) != 0) {
			return EOF;
		}
	}

	return (int32_t) c;
}

int32_t
io_proxy_vprintf(io_write_proxy_t* io, const char* format, va_list vlist)
{
	int32_t res;
	char buf[IO_PROXY_PRINTF_BUFFER_SIZE];

	res = vsnprintf(buf, sizeof(buf), format, vlist);

	if (res <= 0) {
		return res;
	}

	return (int32_t) io_proxy_write(io, buf, (uint64_t) res);
}

int32_t
io_proxy_printf(io_write_proxy_t* io, const char* format, ...)
{
	va_list args;
	int32_t res;

	va_start(args, format);
	res = io_proxy_vprintf(io, format, args);
	va_end(args);

	return res;
}

ssize_t
io_proxy_read(io_read_proxy_t* io, void* buf, size_t n_bytes)
{
	uint64_t init_n_bytes = n_bytes;

	if (_init_fn(io) != 0) {
		return -1;
	}

	if (UNLIKELY(!io_proxy_is_reader(io))) {
		err("Can only read from a read proxy");
		return -1;
	}

	if (io->buffer.src == NULL) {
		return (ssize_t) file_proxy_read(&io->file, buf, n_bytes);
	}

	while (n_bytes > 0) {
		if (io->buffer.pos == io->buffer.data_pos) {
			if (_buffer_read_block(io) != 0) {
				break;
			}
		}
		if (io->buffer.pos == 0) {
			// no data left
			break;
		}
		_consumer_buffer_read(&io->buffer, &buf, (uint64_t*) &n_bytes);
	}

	return (ssize_t) (init_n_bytes - n_bytes);
}

int32_t
io_proxy_getc(io_read_proxy_t* io)
{
	int32_t res;

	if (_init_fn(io) != 0) {
		return EOF;
	}

	if (UNLIKELY(!io_proxy_is_reader(io))) {
		err("Can only read from a read proxy");
		return EOF;
	}

	if (io->buffer.src == NULL) {
		res = file_proxy_getc(&io->file);
	}
	else {
		if (io->buffer.pos == io->buffer.data_pos) {
			if (_buffer_read_block(io) != 0) {
				return EOF;
			}
		}
		if (io->buffer.pos == 0) {
			// no data left
			return EOF;
		}

		res = _consumer_buffer_getc(&io->buffer);
	}

	return res;
}

int32_t
io_proxy_getc_unlocked(io_read_proxy_t* io)
{
	int32_t res;

	if (_init_fn(io) != 0) {
		return EOF;
	}

	if (UNLIKELY(!io_proxy_is_reader(io))) {
		err("Can only read from a read proxy");
		return EOF;
	}

	if (io->buffer.src == NULL) {
		res = file_proxy_getc_unlocked(&io->file);
	}
	else {
		if (io->buffer.pos == io->buffer.data_pos) {
			if (_buffer_read_block(io) != 0) {
				return EOF;
			}
		}
		if (io->buffer.pos == 0) {
			// no data left
			return EOF;
		}

		res = _consumer_buffer_getc(&io->buffer);
	}

	return res;
}

char*
io_proxy_gets(io_read_proxy_t* io, char* str, int n)
{
	char c;
	int i;

	for (i = 0; i < n - 1; i++) {
		c = (char) io_proxy_getc(io);
		if (c == EOF) {
			if (i == 0) {
				return NULL;
			}
			break;
		}
		str[i] = c;
		if (c == '\n') {
			i++;
			break;
		}
	}
	str[i] = '\0';
	return str;
}

int32_t
io_proxy_peekc_unlocked(io_read_proxy_t* io)
{
	if (_init_fn(io) != 0) {
		return EOF;
	}

	if (UNLIKELY(!io_proxy_is_reader(io))) {
		err("Can only read from a read proxy");
		return EOF;
	}

	if (io->buffer.src == NULL) {
		return file_proxy_peekc_unlocked(&io->file);
	}

	if (io->buffer.pos == io->buffer.data_pos) {
		if (_buffer_read_block(io) != 0) {
			return EOF;
		}
	}
	if (io->buffer.pos == 0) {
		return EOF;
	}

	return _consumer_buffer_peekc(&io->buffer);
}

int
io_proxy_flush(io_write_proxy_t* io)
{
	if (_init_fn(io) != 0) {
		return -1;
	}

	if (UNLIKELY(!io_proxy_is_writer(io))) {
		err("Cannot flush a read proxy");
		return -1;
	}
	int ret = _commit_write(io, ZSTD_e_end);
	if (ret != 0) {
		return ret;
	}
	return file_proxy_flush(&io->file);
}

int
io_proxy_error(io_proxy_t* io)
{
	// TODO set this flag
	return (io->flags & IO_PROXY_ERROR) != 0;
}


//==========================================================
// Local Helpers.
//

static int
_proxy_init(io_proxy_t* io, uint8_t options)
{
	io->byte_cnt = 0;
	// raw_byte_cnt and parsed_byte_cnt are unioned together, so only clear one
	io->raw_byte_cnt = 0;
	io->initialized = 0;
	io->flags = options;

	io->num = 0;

	return 0;
}

static void
_proxy_free(io_proxy_t* io)
{
	if (io->initialized) {
		if (io_proxy_do_compress(io)) {
			if (io_proxy_is_writer(io)) {
				ZSTD_freeCCtx(io->cctx);
			}
			else {
				ZSTD_freeDCtx(io->dctx);
			}
			// comp_buffer and decomp_buffer alias each other
			_consumer_buffer_free(&io->comp_buffer);
		}
		if (io_proxy_do_encrypt(io)) {
			memset(&io->pkey_digest, 0, sizeof(AES_KEY));
			memset(&io->decrypt_pkey_digest, 0, sizeof(AES_KEY));
			memset(io->iv, 0, AES_BLOCK_SIZE);
			// encrypt_buffer and decrypt_buffer alias each other
			_consumer_buffer_free(&io->encrypt_buffer);
		}
		_consumer_buffer_free(&io->buffer);
	}
}

static void
_io_proxy_set_error(io_proxy_t* io)
{
	io->flags |= IO_PROXY_ERROR;
}

static void
_consumer_buffer_init(consumer_buffer_t* cb, uint64_t size)
{
	cb->src = cf_malloc(size);
	cb->size = size;
	cb->pos = 0;
	cb->data_pos = 0;
}

static void
_consumer_buffer_free(consumer_buffer_t* cb)
{
	if (cb->src != NULL) {
		cf_free(cb->src);
	}
}

/*
 * this method zeros both values the pointers point to if they point to the
 * same value
 *
 * this should be called whenever cb->data_pos changes for any buffer
 */
static void
__zero_if_eq(uint64_t* pos_ptr, uint64_t* dpos_ptr)
{
	if (*pos_ptr == *dpos_ptr) {
		*pos_ptr = 0;
		*dpos_ptr = 0;
	}
}

static int
_consumer_buffer_serialize(const consumer_buffer_t* cb, file_proxy_t* dst)
{
	if (!write_int64(cb->size, dst) || !write_int64(cb->pos, dst) ||
			!write_int64(cb->data_pos, dst)) {
		err("Serializing consumer buffer fields to file failed");
		return -1;
	}

	if (file_proxy_write(dst, cb->src, cb->pos) != cb->pos) {
		err("Serializing consumer buffer data to file failed");
		return -1;
	}

	return 0;
}

static int
_consumer_buffer_deserialize(consumer_buffer_t* cb, file_proxy_t* src)
{
	if (!read_int64(&cb->size, src) || !read_int64(&cb->pos, src) ||
			!read_int64(&cb->data_pos, src)) {
		err("Deserializing consumer buffer fields from file failed");
		return -1;
	}

	cb->src = cf_malloc(cb->size);
	if (cb->src == NULL) {
		err("Unable to malloc %" PRIu64 " bytes for deserialized consumer buffer",
				cb->size);
		return -1;
	}

	if (file_proxy_read(src, cb->src, cb->pos) != cb->pos) {
		err("Deserializing consumer buffer data from file failed");
		cf_free(cb->src);
		return -1;
	}

	return 0;
}

/*
 * reads n_bytes bytes from src into the buffer, updating the src pointer and
 * n_bytes count to the data which is still hasn't been consumed
 */
static void
_consumer_buffer_write(consumer_buffer_t* cb, const void** src, uint64_t *n_bytes)
{
	uint64_t cb_bytes = cb->size - cb->pos;
	uint64_t n = MIN(cb_bytes, *n_bytes);
	memcpy(cb->src + cb->pos, *src, n);

	cb->pos += n;
	*n_bytes -= n;
	*src += n;
}

/*
 * writes a single character to the buffer, assuming there's room
 *
 * if there isn't room, this results in undefined behavior
 */
static void
_consumer_buffer_putc(consumer_buffer_t* cb, char c)
{
	((char*) cb->src)[cb->pos++] = c;
}

/*
 * writes n_bytes bytes from the buffer into dst, updating the src pointer and
 * n_bytes count to the data which is still hasn't been consumed
 */
static void
_consumer_buffer_read(consumer_buffer_t* cb, void** dst, uint64_t *n_bytes)
{
	uint64_t cb_bytes = cb->pos - cb->data_pos;
	uint64_t n = MIN(cb_bytes, *n_bytes);
	memcpy(*dst, cb->src + cb->data_pos, n);
	cb->data_pos += n;
	__zero_if_eq(&cb->pos, &cb->data_pos);

	*n_bytes -= n;
	*dst += n;
}

/*
 * reads the next character from the buffer, assuming there is a next character
 *
 * if there is no next character, this results in undefined behavior
 */
static int32_t
_consumer_buffer_getc(consumer_buffer_t* cb)
{
	int32_t res = (int32_t) ((uint8_t*) cb->src)[cb->data_pos];

	cb->data_pos++;
	__zero_if_eq(&cb->pos, &cb->data_pos);
	return res;
}

/*
 * reads the next character from the buffer, assuming there is a next character,
 * without changing the data_pos field
 *
 * if there is no next character, this results in undefined behavior
 */
static int32_t
_consumer_buffer_peekc(consumer_buffer_t* cb)
{
	return (int32_t) ((uint8_t*) cb->src)[cb->data_pos];
}

/*
 * returns 0 if there is nothing left to be read, 1 if there is more data to be
 * read from the file, and -1 if there was an error
 */
static int
_consumer_buffer_fread(consumer_buffer_t* cb, file_proxy_t* file)
{
	size_t n_bytes = file_proxy_read(file, cb->src + cb->pos, cb->size - cb->pos);

	cb->pos += n_bytes;
	if (file_proxy_eof(file)) {
		return 0;
	}
	else if (n_bytes == 0) {
		err("Failed reading data from file");
		return -1;
	}
	return 1;
}

/*
 * returns the number of bytes left to be written, or -1 if there was an error
 */
static int64_t
_consumer_buffer_fwrite(consumer_buffer_t* cb, file_proxy_t* file)
{
	size_t n_bytes = file_proxy_write(file, cb->src + cb->data_pos,
			cb->pos - cb->data_pos);
	if (cb->pos > 0 && n_bytes == 0) {
		err("Failed writing data to file");
		return -1;
	}

	cb->data_pos += n_bytes;
	uint64_t rem = cb->pos - cb->data_pos;
	__zero_if_eq(&cb->pos, &cb->data_pos);

	return (int64_t) rem;
}

/*
 * returns the number of bytes left to be compressed, or -1 on error
 */
static int64_t
_consumer_buffer_compress(io_proxy_t* io, consumer_buffer_t* dst,
		consumer_buffer_t* src, ZSTD_EndDirective z_ed)
{
	ZSTD_outBuffer* dst_out = (ZSTD_outBuffer*) dst;
	ZSTD_inBuffer src_in = {
		.src = src->src,
		.size = src->pos,
		.pos = src->data_pos
	};

	uint64_t rem_bytes = ZSTD_compressStream2(io->cctx, dst_out, &src_in, z_ed);

	if (ZSTD_isError(rem_bytes)) {
		err("Failed to compress data: %s",
				ZSTD_getErrorName(rem_bytes));
		return -1;
	}

	__zero_if_eq((uint64_t*) &src_in.size, (uint64_t*) &src_in.pos);

	src->pos = src_in.size;
	src->data_pos = src_in.pos;

	return (int64_t) (rem_bytes + (src_in.size - src_in.pos));
}

/*
 * returns 1 if we made progress, 0 if more data needs to be read (progress may
 * have been made), or -1 on error
 */
static int
_consumer_buffer_decompress(io_proxy_t* io, consumer_buffer_t* dst,
		consumer_buffer_t* src)
{
	ZSTD_outBuffer* dst_out = (ZSTD_outBuffer*) dst;
	ZSTD_inBuffer src_in = {
		.src = src->src,
		.size = src->pos,
		.pos = src->data_pos
	};

	uint64_t rem_bytes = ZSTD_decompressStream(io->dctx, dst_out, &src_in);

	if (ZSTD_isError(rem_bytes)) {
		err("Failed to decompress data: %s",
				ZSTD_getErrorName(rem_bytes));
		return -1;
	}

	src->data_pos = src_in.pos;
	__zero_if_eq(&src->pos, &src->data_pos);

	if (src_in.pos < src_in.size) {
		// some input has not been consumed, but we know the bottleneck is in
		// the destination buffer
		return 1;
	}
	if (dst_out->pos < dst_out->size) {
		// we were not able to completely fill the output buffer, so request
		// more data
		return 0;
	}
	return 1;
}

/*
 * Ends the current compression block in the comp buffer, but doesn't write the
 * changes through the remaining buffers. This may expand the size of the comp
 * buffer.
 */
static int
_comp_buffer_end_block(io_proxy_t* io)
{
	uint64_t rem_bytes;

	while ((rem_bytes = ZSTD_endStream(io->cctx,
					(ZSTD_outBuffer*) &io->comp_buffer)) > 0 &&
			!ZSTD_isError(rem_bytes)) {

		uint64_t new_size = 2 * rem_bytes + io->comp_buffer.size;
		// expand the size of the compression buffer
		void* new_src = cf_realloc(io->comp_buffer.src, new_size);

		if (new_src == NULL) {
			err("Failed to reallocate %" PRIu64 " bytes for expanded "
					"compression buffer",
					new_size);
			return -1;
		}

		io->comp_buffer.src = new_src;
		io->comp_buffer.size = new_size;
	}

	if (ZSTD_isError(rem_bytes)) {
		err("Failed to compress data: %s",
				ZSTD_getErrorName(rem_bytes));
		return -1;
	}

	return 0;
}

/*
 * encrypts data from src into dst using AES CTR mode
 *
 * if all of src was encrypted into dst, 1 is returned, otherwise is 0 is
 * returned there is still some data in src that coulnd't fit in dst
 */
static int
_consumer_buffer_encrypt(io_proxy_t* io, consumer_buffer_t* dst,
		consumer_buffer_t* src)
{
	uint64_t src_len = src->pos - src->data_pos;
	uint64_t dst_len = dst->size - dst->pos;
	uint64_t len = MIN(src_len, dst_len);
	void* dst_buf = dst->src + dst->pos;
	void* src_buf = src->src + src->data_pos;

	CRYPTO_ctr128_encrypt(src_buf, dst_buf, len, &io->pkey_digest,
			io->iv, io->ecount_buf, &io->num, (block128_f) AES_encrypt);

	src->data_pos += len;
	__zero_if_eq(&src->pos, &src->data_pos);
	dst->pos += len;
	return len == src_len;
}

/*
 * decrypts all data from src into dst, which it assumed will fit
 *
 * returns 1 if progress was made, or 0 if no progress was made
 */
static void
_consumer_buffer_decrypt(io_proxy_t* io, consumer_buffer_t* dst,
		consumer_buffer_t* src)
{
	// encryption and decryption are the same operation
	_consumer_buffer_encrypt(io, dst, src);
}


static __attribute__((pure)) uint64_t
_get_pkey_digest_len(uint8_t flags)
{
	// if doing AES128, key size is 16, else its 32
	return (uint64_t) ((flags & IO_PROXY_ENCRYPT_MASK) << 4);
}

static __attribute__((pure)) bool
_at_eof(io_proxy_t* io)
{
	return (io->flags & IO_READ_PROXY_EOF) == IO_READ_PROXY_EOF;
}

/*
 * calculates a buffer size to use for the output (write) buffer, given the
 * options that are enabled
 */
static __attribute__((pure)) uint64_t
_calc_output_buffer_len(const io_proxy_t* io)
{
	if (io_proxy_do_encrypt(io)) {
		if (io_proxy_do_compress(io)) {
			return MAX(ZSTD_CStreamOutSize(), N_BUFFERED_BLOCKS * AES_BLOCK_SIZE);
		}
		return N_BUFFERED_BLOCKS * AES_BLOCK_SIZE;
	}
	if (io_proxy_do_compress(io)) {
		return ZSTD_CStreamOutSize();
	}
	return IO_PROXY_DEFAULT_BUFFER_SIZE;
}

/*
 * calculates a buffer size to use for the input (read) buffer, given the
 * options that are enabled
 */
static __attribute__((pure)) uint64_t
_calc_input_buffer_len(const io_proxy_t* io)
{
	if (io_proxy_do_encrypt(io)) {
		if (io_proxy_do_compress(io)) {
			return MAX(ZSTD_CStreamInSize(), N_BUFFERED_BLOCKS * AES_BLOCK_SIZE);
		}
		return N_BUFFERED_BLOCKS * AES_BLOCK_SIZE;
	}
	if (io_proxy_do_compress(io)) {
		return ZSTD_CStreamInSize();
	}
	return IO_PROXY_DEFAULT_BUFFER_SIZE;
}


/*
 * generates a random IV (initialization vector) for encryption
 *
 * note: in OpenSSL, IV's are in big endian no matter the endianness of the
 * architecture
 */
static void
_gen_iv(uint8_t iv[AES_BLOCK_SIZE])
{
	// most significant 32 bytes are current time (modulo ~136 years)
	uint32_t v3 = (uint32_t) time(NULL);
#ifdef __APPLE__
	*((uint32_t*) &iv[0]) = OSSwapHostToBigInt32(v3);
#else
	*((uint32_t*) &iv[0]) = htobe32(v3);
#endif /* __APPLE__ */

	// least significant 96 bytes are random
	// create a new random instance, which uses bytes generated by arc4random
	as_random random;
	as_random_init(&random);
	uint32_t v1 = as_random_next_uint32(&random);
	uint64_t v2 = as_random_next_uint64(&random);
	*((uint32_t*) &iv[4]) = v1;
	*((uint64_t*) &iv[8]) = v2;
}


/*
 * adds the value "val" to the 128-bit integer stored at counter in big-endian
 * format
 *
 * src and dst may overlap
 */
static void
_ctr128_add_to(uint8_t dst[AES_BLOCK_SIZE], const uint8_t src[AES_BLOCK_SIZE],
		uint64_t val)
{
	uint64_t v1 = htobe64(*(const uint64_t*) &src[0]);
	uint64_t v2 = htobe64(*(const uint64_t*) &src[8]);
	uint16_t z = 0;

	__asm__("add %[v2], %[val], %[v2]\n\t"
			"adc %[v1], z, %[v1]"
			: [v1] "+r" (v1),
			  [v2] "+&r" (v2)
			: [val] "r" (val),
			  [z] "r" (z)
			: "cc");
	v1 = be64toh(v1);
	v2 = be64toh(v2);
	__asm__("mov (%[dst]), %[v1]\n\t"
			"mov 0x8(%[dst]), %[v2]"
			:
			: [v1] "r" (v1),
			  [v2] "r" (v2),
			  [dst] "r" (dst)
			: "memory");
}

/*
 * subtracts the value "val" from the 128-bit integer stored at counter in
 * big-endian format
 *
 * src and dst may overlap
 */
static void
_ctr128_sub_from(uint8_t dst[AES_BLOCK_SIZE], const uint8_t src[AES_BLOCK_SIZE],
		uint64_t val)
{
	// *(__uint128_t*) dst =  (*(const __uint128_t*) src) - 1;

	uint64_t v1 = htobe64(*(const uint64_t*) &src[0]);
	uint64_t v2 = htobe64(*(const uint64_t*) &src[8]);
	uint16_t z = 0;

	__asm__("sub %[v2], %[val], %[v2]\n\t"
			"sbc %[v1], z, %[v1]"
			: [v1] "+r" (v1),
			  [v2] "+&r" (v2)
			: [val] "r" (val),
			  [z] "r" (z)
			: "cc");
	v1 = be64toh(v1);
	v2 = be64toh(v2);
	__asm__("mov (%[dst]), %[v1]\n\t"
			"mov 0x8(%[dst]), %[v2]"
			:
			: [v1] "r" (v1),
			  [v2] "r" (v2),
			  [dst] "r" (dst)
			: "memory");
}

static int
_init_fn(io_write_proxy_t* io)
{
	uint32_t buf_len;
	bool write = io_proxy_is_writer(io);

	if (UNLIKELY(!io->initialized)) {

		if (io->flags & IO_PROXY_DESERIALIZE) {
			// if deserializing the io_proxy, make sure the flags match what
			// they are expected to be
			if ((io->flags & IO_PROXY_INIT_FLAGS) !=
					(io->deserialized_flags & IO_PROXY_INIT_FLAGS)) {
				err("io_proxy flags (%02x) do not match the serialized "
						"flags (%02x), make sure the io_proxy is initialized in "
						"the same matter as it was when serialized.",
						io->flags & IO_PROXY_INIT_FLAGS,
						io->deserialized_flags & IO_PROXY_INIT_FLAGS);
				return -1;
			}

			if (!io_proxy_do_compress(io)) {
				memset(&io->comp_buffer, 0, sizeof(io->comp_buffer));
			}

			if (io_proxy_do_encrypt(io)) {
				// for encryption, we need to encrypt the IV back into ecount_buf
				// and increment IV for the next encryption block
				AES_encrypt(io->iv, io->ecount_buf, &io->pkey_digest);
				// increment the IV for the next block of encrypted data
				_ctr128_add_to(io->iv, io->iv, 1);
			}
			else {
				memset(&io->encrypt_buffer, 0, sizeof(io->encrypt_buffer));
			}

			// skip initialization of everything else, as this has already been
			// done in deserialize
			io->initialized = 1;
			return 0;
		}

		buf_len = (uint32_t) (write ? _calc_output_buffer_len(io) :
				_calc_input_buffer_len(io));

		_consumer_buffer_init(&io->buffer, buf_len);

		if (io_proxy_do_compress(io)) {
			// comp_buffer and decomp_buffer alias each other
			_consumer_buffer_init(&io->comp_buffer, buf_len);
		}
		else {
			memset(&io->comp_buffer, 0, sizeof(io->comp_buffer));
		}

		if (io_proxy_do_encrypt(io)) {
			// encrypt_buffer and decrypt_buffer alias each other
			_consumer_buffer_init(&io->encrypt_buffer, buf_len);

			if (write) {
				// generate an IV, encrypt it, and store it at the beginning of
				// the file
				_gen_iv(io->iv);
				void* ecount_buf_ptr = (void*) io->ecount_buf;
				uint64_t n_bytes = AES_BLOCK_SIZE;

				AES_encrypt(io->iv, io->ecount_buf, &io->pkey_digest);

				// write the encrypted IV directly to the encrypt buffer,
				// otherwise we will end up trying to compress/encrypt the
				// key again
				_consumer_buffer_write(&io->encrypt_buffer,
						(const void**) &ecount_buf_ptr, &n_bytes);
				if (n_bytes != 0) {
					err("Unable to write encrypted IV to buffer");
					return -1;
				}

				// increment byte_cnt and raw_byte_cnt (by the same amount
				// since the encrypted IV can't be compressed) by the number
				// of bytes just read from the file
				io->raw_byte_cnt += AES_BLOCK_SIZE;
			}
			else {
				// decrypt the IV, which is at the very beginning of the file
				consumer_buffer_t iv_buf;
				_consumer_buffer_init(&iv_buf, AES_BLOCK_SIZE);

				// read it directly from the file to bypass
				// decryption/decompression steps
				int status = _consumer_buffer_fread(&iv_buf, &io->file);
				if (status < 0) {
					_consumer_buffer_free(&iv_buf);
					return status;
				}
				// the entire IV must have been at the beginning of the file,
				// so we should have been able to successfully read all 32 bytes
				// of it
				if (iv_buf.pos != iv_buf.size) {
					err("Error when reading IV from file: only %" PRIu64 " "
							"bytes were found, but expected %d",
							iv_buf.pos, AES_BLOCK_SIZE);
					_consumer_buffer_free(&iv_buf);
					return -1;
				}
				AES_decrypt(iv_buf.src, io->iv, &io->decrypt_pkey_digest);
				_consumer_buffer_free(&iv_buf);

				// increment byte_cnt by the number of bytes just read from the file
				io->byte_cnt += AES_BLOCK_SIZE;
			}

			// increment the IV for the first block of encrypted data
			_ctr128_add_to(io->iv, io->iv, 1);
		}
		else {
			memset(&io->encrypt_buffer, 0, sizeof(io->encrypt_buffer));
		}

		io->initialized = 1;
	}
	return 0;
}

/*
 * To commit a write to the file, the buffered raw data (stored in io->buffer)
 * is cascaded down through buffers, with one per operation done on the data
 * (encryption or compression). For compression, raw data is read from
 * io->buffer, compressed, then stored in io->compress_buffer. For encryption,
 * data is either read from io->buffer (no compression) or io->compress_buffer
 * and encrypted into the io->encrypt_buffer. Lastly, the final data is written
 * directly to the file.
 *
 * With end directive z_ed = ZSTD_e_continue, this process happens repeatedly
 * until io->buffer is emptied. With end directive z_ed = ZSTD_e_end, this
 * process happens repeatedly until no data is left in any of the buffers.
 */
static int
_commit_write(io_write_proxy_t* io, ZSTD_EndDirective z_ed)
{
	// buffer in which to find the partially processed data at each step
	consumer_buffer_t *trans_buffer;
	uint64_t rem_bytes;

	// we will be consuming all of io->buffer, so add that to the total raw
	// byte count
	io->raw_byte_cnt += io->buffer.pos - io->buffer.data_pos;

	do {
		trans_buffer = &io->buffer;
		rem_bytes = 0;

		if (io_proxy_do_compress(io)) {
			int64_t rem = _consumer_buffer_compress(io, &io->comp_buffer,
					trans_buffer, z_ed);
			if (rem < 0) {
				return (int) rem;
			}
			rem_bytes += (uint64_t) rem;

			trans_buffer = &io->comp_buffer;
		}
		if (io_proxy_do_encrypt(io)) {
			int all_consumed = _consumer_buffer_encrypt(io, &io->encrypt_buffer,
					trans_buffer);
			rem_bytes += (uint64_t) !all_consumed;
			trans_buffer = &io->encrypt_buffer;
		}

		// write the contents of the buffer to the fd now
		uint64_t n_bytes = trans_buffer->pos - trans_buffer->data_pos;
		int64_t res = _consumer_buffer_fwrite(trans_buffer, &io->file);
		if (res < 0) {
			// an io error happened on the file
			_io_proxy_set_error(io);
			return (int) res;
		}
		rem_bytes += (uint64_t) res;
		rem_bytes += io->buffer.pos - io->buffer.data_pos;
		io->byte_cnt += n_bytes - (trans_buffer->pos - trans_buffer->data_pos);

		// if z_ed is ZSTD_e_end, we need to flush all buffers, otherwise we
		// only need to fully flush the first buffer
	} while (z_ed == ZSTD_e_end ? rem_bytes > 0 : io->buffer.pos != 0);

	return 0;
}

/*
 * To read a block of data from the file, it first has to be decrypted and/or
 * decompressed. This process is done in the reverse order of writing data,
 * so data read from the file first goes into either io->decrypt_buffer (if
 * compression is disabled) or io->decomp_buffer. If it goes into the compress
 * buffer, it is decompressed into either io->buffer (if encryption is disabled)
 * or io->decrypt_buffer. With data in io->decrypt_buffer, it is always
 * decrypted into io->buffer.
 *
 * These conditions are checked in reverse order, though, i.e. we first see if
 * there is any outstanding data in the decrypt buffer. If there is, we decrypt
 * it and check if io->buffer has become full from this operation. If so, we are
 * done, so we can immediately return. Otherwise, we move onto the decompression
 * buffer and follow the same process. Lastly, we would read straight from the
 * file. This process is always repeated until either io->buffer is filled, EOF
 * is reached, or an error occurs.
 *
 * Returns 0 on success, < 0 on error.
 */
static int
_buffer_read_block(io_write_proxy_t* io)
{
	// buffer in which to find the partially processed data at each step
	consumer_buffer_t* trans_buffer;

	consumer_buffer_t* decomp_buffer;
	consumer_buffer_t* decrypt_buffer;
	consumer_buffer_t* in_buffer = &io->buffer;

	bool decompress = io_proxy_do_compress(io);
	bool decrypt = io_proxy_do_encrypt(io);

	// since we have consumed all bytes from io->buffer, but since its pos has
	// been reset, the only way to count the amount of data that was in
	// io->buffer is to take the total amount of data that was in all the
	// buffers (io->byte_cnt - io->parsed_byte_cnt) and subtract the amount of
	// data queued for compression and encryption
	uint64_t parsed_bytes = io->byte_cnt - io->parsed_byte_cnt;

	if (decompress) {
		decomp_buffer = in_buffer;
		in_buffer = &io->decomp_buffer;

		parsed_bytes -= io->decomp_buffer.pos - io->decomp_buffer.data_pos;
	}

	if (decrypt) {
		decrypt_buffer = in_buffer;
		in_buffer = &io->decrypt_buffer;

		parsed_bytes -= io->decrypt_buffer.pos - io->decrypt_buffer.data_pos;
	}

	// parsed_bytes is now the amount of data that was in io->buffer
	io->parsed_byte_cnt += parsed_bytes;

	do {
		trans_buffer = in_buffer;

		if (decrypt) {
			_consumer_buffer_decrypt(io, decrypt_buffer, trans_buffer);
			if (io->buffer.pos == io->buffer.size) {
				break;
			}
			trans_buffer = decrypt_buffer;
		}
		if (decompress) {
			int progress = _consumer_buffer_decompress(io, decomp_buffer,
					trans_buffer);
			if (progress < 0) {
				return progress;
			}
			if (progress > 0) {
				continue;
			}
		}

		if (_at_eof(io)) {
			break;
		}

		// to count the number of bytes read directly from the file, which is
		// just the pos of the buffer after the read minus the pos before
		io->byte_cnt -= in_buffer->pos;
		int status = _consumer_buffer_fread(in_buffer, &io->file);
		if (status < 0) {
			// an io error happened on the file
			_io_proxy_set_error(io);
			return status;
		}
		io->byte_cnt += in_buffer->pos;

		if (status == 0) {
			io->flags |= IO_READ_PROXY_EOF;
		}
	} while (io->buffer.pos < io->buffer.size);

	return 0;
}

