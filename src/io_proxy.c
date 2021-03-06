/*
 * Copyright 2021-2021 Aerospike, Inc.
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

static int _proxy_init(io_proxy_t* io, FILE* file, uint8_t options);
static void _io_proxy_set_error(io_proxy_t* io);
static void _consumer_buffer_init(consumer_buffer_t* cb, uint64_t size);
static void _consumer_buffer_free(consumer_buffer_t* cb);
static void __zero_if_eq(uint64_t* pos, uint64_t* data_pos);
static void _consumer_buffer_write(consumer_buffer_t* cb, const void** src,
		uint64_t *n_bytes);
static void _consumer_buffer_putc(consumer_buffer_t* cb, char c);
static void _consumer_buffer_read(consumer_buffer_t* cb, void** dst,
		uint64_t *n_bytes);
static int32_t _consumer_buffer_getc(consumer_buffer_t* cb);
static int32_t _consumer_buffer_peekc(consumer_buffer_t* cb);
static int _consumer_buffer_fread(consumer_buffer_t* cb, FILE* file);
static int64_t _consumer_buffer_fwrite(consumer_buffer_t* cb, FILE* file);
static int64_t _consumer_buffer_compress(io_proxy_t* io, consumer_buffer_t* dst,
		consumer_buffer_t* src, ZSTD_EndDirective z_ed);
static int _consumer_buffer_decompress(io_proxy_t* io, consumer_buffer_t* dst,
		consumer_buffer_t* src);
static int _consumer_buffer_encrypt(io_proxy_t* io, consumer_buffer_t* dst,
		consumer_buffer_t* src);
static void _consumer_buffer_decrypt(io_proxy_t* io, consumer_buffer_t* dst,
		consumer_buffer_t* src);
static __attribute__((pure)) bool _is_write_proxy(io_proxy_t* io);
static __attribute__((pure)) bool _is_read_proxy(io_proxy_t* io);
static __attribute__((pure)) bool _do_compress(const io_proxy_t* io);
static __attribute__((pure)) bool _do_encrypt(const io_proxy_t* io);
static __attribute__((pure)) uint64_t _get_pkey_digest_len(uint8_t flags);
static __attribute__((pure)) bool _at_eof(io_proxy_t* io);
static __attribute__((pure)) uint64_t _calc_output_buffer_len(
		const io_proxy_t* io);
static __attribute__((pure)) uint64_t _calc_input_buffer_len(
		const io_proxy_t* io);
static void _gen_iv(uint8_t iv[16]);
static void _ctr128_add_to(uint8_t dst[16], uint8_t src[16], uint64_t val);
static int _init_fn(io_write_proxy_t* io, bool write);
static int _init_write_fn(io_write_proxy_t* io);
static int _init_read_fn(io_write_proxy_t* io);
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

int
io_proxy_read_private_key_file(const char* pkey_file_path,
		encryption_key_t* pkey_buf)
{
	FILE* pkey_file;
	EVP_PKEY* pkey;

	pkey_file = fopen(pkey_file_path, "r");
	if (pkey_file == NULL) {
		fprintf(stderr, "Could not open private key file \"%s\"\n",
				pkey_file_path);
		return -1;
	}

	// read the private key into the OpenSSL EVP_PKEY struct
	pkey = PEM_read_PrivateKey(pkey_file, NULL, NULL, NULL);
	fclose(pkey_file);
	if (pkey == NULL) {
		fprintf(stderr, "Unable to parse private key, make sure the key is in "
				"PEM format\n");
		return -1;
	}

	pkey_buf->data = NULL;
	// encode the key into a temporary buffer
	pkey_buf->len = (uint64_t) i2d_PrivateKey(pkey, &pkey_buf->data);

	EVP_PKEY_free(pkey);
	if (((int64_t) pkey_buf->len) <= 0) {
		printf("OpenSSL error: %s\n",
				ERR_error_string(ERR_get_error(), NULL));
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
io_write_proxy_init(io_write_proxy_t* io, FILE* file)
{
	return _proxy_init(io, file, IO_WRITE_PROXY);
}

int
io_read_proxy_init(io_write_proxy_t* io, FILE* file)
{
	return _proxy_init(io, file, IO_READ_PROXY);
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
		fprintf(stderr, "EVP_DigestInit_ex() failed\n");
		return -1;
	}

	if (EVP_DigestUpdate(ctx, pkey->data, pkey->len) == 0) {
		EVP_MD_CTX_destroy(ctx);
		fprintf(stderr, "EVP_DigestUpdate() failed\n");
		return -1;
	}

	pkey_digest_len = _get_pkey_digest_len((uint8_t) encrypt_mode);
	// since we are using SHA-256, the digest should be 32 bytes
	pkey_digest = (uint8_t*) cf_malloc(digest_len);

	if (EVP_DigestFinal_ex(ctx, pkey_digest, &d_len) == 0 ||
			d_len > digest_len) {
		EVP_MD_CTX_destroy(ctx);
		fprintf(stderr, "EVP_DigestFinal_ex() failed\n");
		return -1;
	}
	EVP_MD_CTX_destroy(ctx);

	int res = AES_set_encrypt_key(pkey_digest, (int) (pkey_digest_len * 8),
			&io->pkey_digest);
	if (res < 0) {
		fprintf(stderr, "Failed to initialize encryption key\n");
		return -1;
	}

	if (_is_read_proxy(io)) {
		res = AES_set_decrypt_key(pkey_digest, (int) (pkey_digest_len * 8),
				&io->decrypt_pkey_digest);
		if (res < 0) {
			fprintf(stderr, "Failed to initialize decryption key\n");
			return -1;
		}
	}

	memset(pkey_digest, 0, digest_len);
	cf_free(pkey_digest);

	io->flags |= (uint8_t) encrypt_mode;
	__atomic_thread_fence(__ATOMIC_RELEASE);
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

	__atomic_thread_fence(__ATOMIC_RELEASE);
	return res;
}

int
io_proxy_init_compression(io_proxy_t* io, compression_opt compress_mode)
{
	if (compress_mode == IO_PROXY_COMPRESS_NONE) {
		// do nothing if compression isn't enabled (this isn't an error)
		return 0;
	}

	if (_is_write_proxy(io)) {
		io->cctx = ZSTD_createCCtx();
	}
	else {
		io->dctx = ZSTD_createDCtx();
	}
	io->flags |= (uint8_t) compress_mode;

	__atomic_thread_fence(__ATOMIC_RELEASE);
	return 0;
}

void
io_proxy_free(io_proxy_t* io)
{
	if (_do_compress(io)) {
		if (_is_write_proxy(io)) {
			ZSTD_freeCCtx(io->cctx);
		}
		else {
			ZSTD_freeDCtx(io->dctx);
		}
		if (io->initialized) {
			// comp_buffer and decomp_buffer alias each other
			_consumer_buffer_free(&io->comp_buffer);
		}
	}
	if (_do_encrypt(io)) {
		memset(&io->pkey_digest, 0, sizeof(AES_KEY));
		memset(&io->decrypt_pkey_digest, 0, sizeof(AES_KEY));

		if (io->initialized) {
			memset(io->iv, 0, AES_BLOCK_SIZE);
			// encrypt_buffer and decrypt_buffer alias each other
			_consumer_buffer_free(&io->encrypt_buffer);
		}
	}
	if ((_do_compress(io) || _do_encrypt(io)) && io->initialized) {
		_consumer_buffer_free(&io->buffer);
	}
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

ssize_t
io_proxy_write(io_write_proxy_t* io, const void* buf, size_t n_bytes)
{
	uint64_t init_n_bytes = n_bytes;

	__atomic_thread_fence(__ATOMIC_ACQUIRE);

	if (_init_write_fn(io) != 0) {
		return -1;
	}

	if (UNLIKELY(!_is_write_proxy(io))) {
		fprintf(stderr, "Can only write from a write proxy\n");
		return -1;
	}

	if (io->buffer.src == NULL) {
		return (ssize_t) fwrite(buf, 1, n_bytes, io->fd);
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

	__atomic_thread_fence(__ATOMIC_RELEASE);

	return (ssize_t) (init_n_bytes - n_bytes);
}

int32_t
io_proxy_putc(io_write_proxy_t* io, char c)
{
	__atomic_thread_fence(__ATOMIC_ACQUIRE);

	if (_init_write_fn(io) != 0) {
		return -1;
	}

	if (UNLIKELY(!_is_write_proxy(io))) {
		fprintf(stderr, "Can only write from a write proxy\n");
		return -1;
	}

	if (io->buffer.src == NULL) {
		return (int32_t) putc(c, io->fd);
	}

	_consumer_buffer_putc(&io->buffer, c);
	if (io->buffer.pos == io->buffer.size) {
		if (_commit_write(io, ZSTD_e_continue) != 0) {
			return EOF;
		}
	}

	__atomic_thread_fence(__ATOMIC_RELEASE);

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

	__atomic_thread_fence(__ATOMIC_ACQUIRE);

	if (_init_read_fn(io) != 0) {
		return -1;
	}

	if (UNLIKELY(!_is_read_proxy(io))) {
		fprintf(stderr, "Can only read from a read proxy\n");
		return -1;
	}

	if (io->buffer.src == NULL) {
		return (ssize_t) fread(buf, 1, n_bytes, io->fd);
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

	__atomic_thread_fence(__ATOMIC_RELEASE);

	return (ssize_t) (init_n_bytes - n_bytes);
}

int32_t
io_proxy_getc(io_read_proxy_t* io)
{
	int32_t res;

	__atomic_thread_fence(__ATOMIC_ACQUIRE);

	if (_init_read_fn(io) != 0) {
		return -1;
	}

	if (UNLIKELY(!_is_read_proxy(io))) {
		fprintf(stderr, "Can only read from a read proxy\n");
		return -1;
	}

	if (io->buffer.src == NULL) {
		res = getc(io->fd);
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

	__atomic_thread_fence(__ATOMIC_RELEASE);

	return res;
}

int32_t
io_proxy_getc_unlocked(io_read_proxy_t* io)
{
	int32_t res;

	__atomic_thread_fence(__ATOMIC_ACQUIRE);

	if (_init_read_fn(io) != 0) {
		return -1;
	}

	if (UNLIKELY(!_is_read_proxy(io))) {
		fprintf(stderr, "Can only read from a read proxy\n");
		return -1;
	}

	if (io->buffer.src == NULL) {
		res = getc_unlocked(io->fd);
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

	__atomic_thread_fence(__ATOMIC_RELEASE);

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
	int32_t c;

	__atomic_thread_fence(__ATOMIC_ACQUIRE);

	if (_init_read_fn(io) != 0) {
		return -1;
	}

	if (UNLIKELY(!_is_read_proxy(io))) {
		fprintf(stderr, "Can only read from a read proxy\n");
		return -1;
	}

	if (io->buffer.src == NULL) {
		c = getc_unlocked(io->fd);
		ungetc(c, io->fd);

		return c;
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
	__atomic_thread_fence(__ATOMIC_ACQUIRE);

	if (UNLIKELY(!_is_write_proxy(io))) {
		fprintf(stderr, "Cannot flush a read proxy\n");
		return -1;
	}
	int ret = _commit_write(io, ZSTD_e_end);
	if (ret != 0) {
		return ret;
	}
	fflush(io->fd);

	__atomic_thread_fence(__ATOMIC_RELEASE);

	return 0;
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
_proxy_init(io_proxy_t* io, FILE* file, uint8_t options)
{
	io->fd = file;
	io->initialized = 0;
	io->flags = options;

	io->num = 0;

	__atomic_thread_fence(__ATOMIC_RELEASE);
	return 0;
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
	uint64_t zero = 0;
	uint64_t pos = *pos_ptr;
	uint64_t dpos = *dpos_ptr;
	__asm__("cmp %[pos], %[dpos]\n\t"
			"cmove %[zero], %[pos]\n\t"
			"cmove %[zero], %[dpos]\n\t"
			: [pos] "+r" (pos),
			  [dpos] "+r" (dpos)
			: [zero] "r" (zero)
			: "cc");
	*pos_ptr = pos;
	*dpos_ptr = dpos;
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
	int32_t res = (int32_t) ((char*) cb->src)[cb->data_pos];

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
	return (int32_t) ((char*) cb->src)[cb->data_pos];
}

/*
 * returns 0 if there is nothing left to be read, 1 if there is more data to be
 * read from the file, and -1 if there was an error
 */
static int
_consumer_buffer_fread(consumer_buffer_t* cb, FILE* file)
{
	size_t n_bytes = fread(cb->src + cb->pos, 1, cb->size - cb->pos, file);
	if (ferror(file)) {
		fprintf(stderr, "Failed reading data from file\n");
		return -1;
	}

	cb->pos += n_bytes;
	if (feof(file)) {
		return 0;
	}
	return 1;
}

/*
 * returns the number of bytes left to be written, or -1 if there was an error
 */
static int64_t
_consumer_buffer_fwrite(consumer_buffer_t* cb, FILE* file)
{
	size_t n_bytes = fwrite(cb->src + cb->data_pos, 1, cb->pos - cb->data_pos,
			file);
	if (ferror(file)) {
		fprintf(stderr, "Failed writing data to file\n");
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
		fprintf(stderr, "Failed to compress data: %s\n",
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
		fprintf(stderr, "Failed to decompress data: %s\n",
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


static __attribute__((pure)) bool
_is_write_proxy(io_proxy_t* io)
{
	return (io->flags & IO_PROXY_TYPE_MASK) == IO_WRITE_PROXY;
}

static __attribute__((pure)) bool
_is_read_proxy(io_proxy_t* io)
{
	return (io->flags & IO_PROXY_TYPE_MASK) == IO_READ_PROXY;
}

static __attribute__((pure)) bool
_do_compress(const io_proxy_t* io)
{
	return (io->flags & IO_PROXY_COMPRESS_MASK) != 0;
}

static __attribute__((pure)) bool
_do_encrypt(const io_proxy_t* io)
{
	return (io->flags & IO_PROXY_ENCRYPT_MASK) != 0;
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
	if (_do_encrypt(io)) {
		if (_do_compress(io)) {
			return MAX(ZSTD_CStreamOutSize(), N_BUFFERED_BLOCKS * AES_BLOCK_SIZE);
		}
		return N_BUFFERED_BLOCKS * AES_BLOCK_SIZE;
	}
	if (_do_compress(io)) {
		return ZSTD_CStreamOutSize();
	}
	// no buffer is needed for straight reading/writing
	return 0;
}

/*
 * calculates a buffer size to use for the input (read) buffer, given the
 * options that are enabled
 */
static __attribute__((pure)) uint64_t
_calc_input_buffer_len(const io_proxy_t* io)
{
	if (_do_encrypt(io)) {
		if (_do_compress(io)) {
			return MAX(ZSTD_CStreamInSize(), N_BUFFERED_BLOCKS * AES_BLOCK_SIZE);
		}
		return N_BUFFERED_BLOCKS * AES_BLOCK_SIZE;
	}
	if (_do_compress(io)) {
		return ZSTD_CStreamInSize();
	}
	// no buffer is needed for straight reading/writing
	return 0;
}


/*
 * generates a random IV (initialization vector) for encryption
 *
 * note: in OpenSSL, IV's are in big endian no matter the endianness of the
 * architecture
 */
static void
_gen_iv(uint8_t iv[16])
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
_ctr128_add_to(uint8_t dst[16], uint8_t src[16], uint64_t val)
{
#ifdef __APPLE__
	uint64_t v1 = OSSwapHostToBigInt64(*(uint64_t*) &src[0]);
	uint64_t v2 = OSSwapHostToBigInt64(*(uint64_t*) &src[8]);
#else
	uint64_t v1 = htobe64(*(uint64_t*) &src[0]);
	uint64_t v2 = htobe64(*(uint64_t*) &src[8]);
#endif /* __APPLE__ */
	__asm__("addq %[val], %[v2]\n\t"
			"adcq $0, %[v1]"
			: [v1] "+r" (v1),
			  [v2] "+&r" (v2)
			: [val] "r" (val)
			: "cc");
#ifdef __APPLE__
	v1 = OSSwapBigToHostInt64(v1);
	v2 = OSSwapBigToHostInt64(v2);
#else
	v1 = be64toh(v1);
	v2 = be64toh(v2);
#endif /* __APPLE__ */
	__asm__("movq %[v1], (%[dst])\n\t"
			"movq %[v2], 0x8(%[dst])"
			:
			: [v1] "r" (v1),
			  [v2] "r" (v2),
			  [dst] "r" (dst)
			: "memory");
}

static int
_init_fn(io_write_proxy_t* io, bool write)
{
	uint32_t buf_len;

	if (UNLIKELY(!io->initialized)) {
		buf_len = (uint32_t) (write ? _calc_output_buffer_len(io) :
				_calc_input_buffer_len(io));

		if (buf_len > 0) {
			_consumer_buffer_init(&io->buffer, buf_len);
		}
		else {
			memset(&io->buffer, 0, sizeof(io->buffer));
		}

		if (_do_compress(io)) {
			// comp_buffer and decomp_buffer alias each other
			_consumer_buffer_init(&io->comp_buffer, buf_len);
		}
		else {
			memset(&io->comp_buffer, 0, sizeof(io->comp_buffer));
		}
		if (_do_encrypt(io)) {
			// encrypt_buffer and decrypt_buffer alias each other
			_consumer_buffer_init(&io->encrypt_buffer, buf_len);

			if (write) {
				// generate an IV, encrypt it, and store it at the beginning of
				// the file
				_gen_iv(io->iv);
				uint8_t e_iv[AES_BLOCK_SIZE];
				void* e_iv_ptr = (void*) e_iv;
				uint64_t n_bytes = AES_BLOCK_SIZE;

				AES_encrypt(io->iv, e_iv, &io->pkey_digest);

				// write the encrypted IV directly to the encrypt buffer, otherwise we
				// will end up trying to compress/encrypt the key again
				_consumer_buffer_write(&io->encrypt_buffer, (const void**) &e_iv_ptr, &n_bytes);
				if (n_bytes != 0) {
					fprintf(stderr, "Unable to write encrypted IV to buffer\n");
					return -1;
				}
			}
			else {
				// decrypt the IV, which is at the very beginning of the file
				consumer_buffer_t iv_buf;
				_consumer_buffer_init(&iv_buf, AES_BLOCK_SIZE);
				// read it directly from the file to bypass
				// decryption/decompression steps
				int status = _consumer_buffer_fread(&iv_buf, io->fd);
				if (status < 0) {
					return status;
				}
				// the entire IV must have been at the beginning of the file,
				// so we should have been able to successfully read all 32 bytes
				// of it
				if (iv_buf.pos != iv_buf.size) {
					fprintf(stderr, "Error when reading IV from file: only "
							"%" PRIu64 " bytes were found, but expected %d\n",
							iv_buf.pos, AES_BLOCK_SIZE);
					return -1;
				}
				AES_decrypt(iv_buf.src, io->iv, &io->decrypt_pkey_digest);
				_consumer_buffer_free(&iv_buf);
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

static int
_init_write_fn(io_write_proxy_t* io)
{
	return _init_fn(io, true);
}

static int
_init_read_fn(io_write_proxy_t* io)
{
	return _init_fn(io, false);
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

	do {
		trans_buffer = &io->buffer;
		rem_bytes = 0;

		if (_do_compress(io)) {
			int64_t rem = _consumer_buffer_compress(io, &io->comp_buffer,
					trans_buffer, z_ed);
			if (rem < 0) {
				return (int) rem;
			}
			rem_bytes += (uint64_t) rem;

			trans_buffer = &io->comp_buffer;
		}
		if (_do_encrypt(io)) {
			int all_consumed = _consumer_buffer_encrypt(io, &io->encrypt_buffer,
					trans_buffer);
			rem_bytes += (uint64_t) !all_consumed;
			trans_buffer = &io->encrypt_buffer;
		}

		// write the contents of the buffer to the fd now
		int64_t res = _consumer_buffer_fwrite(trans_buffer, io->fd);
		if (res < 0) {
			// an io error happened on the file
			_io_proxy_set_error(io);
			return (int) res;
		}
		rem_bytes += (uint64_t) res;
		rem_bytes += io->buffer.pos - io->buffer.data_pos;

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

	bool decompress = _do_compress(io);
	bool decrypt  = _do_encrypt(io);

	if (decompress) {
		decomp_buffer = in_buffer;
		in_buffer = &io->decomp_buffer;
	}

	if (decrypt) {
		decrypt_buffer = in_buffer;
		in_buffer = &io->decrypt_buffer;
	}

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

		int status = _consumer_buffer_fread(in_buffer, io->fd);
		if (status < 0) {
			// an io error happened on the file
			_io_proxy_set_error(io);
			return status;
		}
		if (status == 0) {
			io->flags |= IO_READ_PROXY_EOF;
		}
	} while (io->buffer.pos < io->buffer.size);
	return 0;
}

