/*
 * Aerospike Backup
 *
 * Copyright (c) 2021-2021 Aerospike, Inc. All rights reserved.
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

 
//==========================================================
// Includes.
//

#include <shared.h>

#include <openssl/aes.h>

#include <zstd.h>

 
//==========================================================
// Typedefs & Constants.
//


/*
 * number of encrypt blocks to buffer (to make one large encrypt call rather
 * than many small ones)
 */
#define N_BUFFERED_BLOCKS 32

/*
 * specifies which type of io_proxy this is (read vs. write)
 */
#define IO_WRITE_PROXY 0x00
#define IO_READ_PROXY  0x08
#define IO_PROXY_TYPE_MASK \
	(IO_WRITE_PROXY | IO_READ_PROXY)

/*
 * set by read_proxy when EOF has been reached
 */
#define IO_READ_PROXY_EOF 0x10

/*
 * set by the io proxy whenever an error occurs
 * can be checked with io_proxy_error
 */
#define IO_PROXY_ERROR 0x20

/*
 * the size in bytes of the buffer used by io_proxy_printf
 */
#define IO_PROXY_PRINTF_BUFFER_SIZE 1024


/*
 * the compression mode to be used on the io proxy
 */
typedef enum {
	IO_PROXY_COMPRESS_NONE = 0,
	IO_PROXY_COMPRESS_ZSTD = 0x04
} compression_opt;

#define IO_PROXY_COMPRESS_MASK \
	((uint8_t) (IO_PROXY_COMPRESS_ZSTD))

/*
 * the encryption mode to be used on the io proxy
 *
 * the literal values of these enums are used to do some bit tricks in the code,
 * make sure if changing/adding modes to modify those bits of code
 */
typedef enum {
	IO_PROXY_ENCRYPT_NONE = 0,
	IO_PROXY_ENCRYPT_AES128 = 0x01,
	IO_PROXY_ENCRYPT_AES256 = 0x02
} encryption_opt;

#define IO_PROXY_ENCRYPT_MASK \
	((uint8_t) (IO_PROXY_ENCRYPT_AES128 | IO_PROXY_ENCRYPT_AES256))


typedef struct encryption_key_s {
	uint8_t* data;
	uint64_t len;
} encryption_key_t;


typedef struct consumer_buffer_s {
	void* src;
	uint64_t size;
	// position of the end of the region containing data
	uint64_t pos;
	// the start position of where the data can be found
	uint64_t data_pos;
} consumer_buffer_t;


typedef struct io_proxy_s {
	// the file that the proxy buffers reads/writes from
	FILE* fd;

	consumer_buffer_t buffer;

	// global offset of this buffer in the file being written to, modulo
	// AES_BLOCK_SIZE
	// used for alignment with encryption, will always be 0 if encryption is off
	uint32_t num;

	// where the option flags are stored
	uint8_t flags;
	// set to true when the read/write buffers have been initialized and the
	// encryption IV has been stored/retrieved
	uint8_t initialized;

	// substruct for compression-related fields
	struct {
		union {
			ZSTD_CCtx* cctx;
			ZSTD_DCtx* dctx;
		};

		union {
			consumer_buffer_t comp_buffer;
			consumer_buffer_t decomp_buffer;
		};
	};

	// substruct for encryption-related fields
	struct __attribute__((aligned(8))) {
		uint8_t iv[AES_BLOCK_SIZE];
		uint8_t ecount_buf[AES_BLOCK_SIZE];
		AES_KEY pkey_digest;
		AES_KEY decrypt_pkey_digest;

		union {
			consumer_buffer_t encrypt_buffer;
			consumer_buffer_t decrypt_buffer;
		};
	};
} io_proxy_t;


typedef io_proxy_t io_write_proxy_t;
typedef io_proxy_t io_read_proxy_t;

 
//==========================================================
// Public API.
//

/*
 * initializes an encryption key with the provided raw data
 */
void encryption_key_init(encryption_key_t*, uint8_t* pkey_data, uint64_t len);

/*
 * reads a private key from the given file into the pkey buffer and
 * initializes/populates the key passed
 */
int io_proxy_read_private_key_file(const char* pkey_file_path,
		encryption_key_t* key);

void encryption_key_free(encryption_key_t*);


/*
 * initiazes io read/write proxies wrapping the given file. These functions by
 * default set the proxies with encryption and compression disabled
 *
 * returns 0 on success and < 0 on failure
 */
int io_write_proxy_init(io_write_proxy_t*, FILE* file);
int io_read_proxy_init(io_read_proxy_t*, FILE* file);

/*
 * enables encrypting of data through this io proxy
 *
 * this must be called before any read/write calls are made on the proxy
 *
 * if encrypt_mode is IO_PROXY_ENCRYPT_NONE, this does nothing and returns 0
 */
int io_proxy_init_encryption(io_proxy_t*, const encryption_key_t* pkey,
		encryption_opt encrypt_mode);

/*
 * reads the encryption key from the PEM file at pkey_file_path
 *
 * this must be called before any read/write calls are made on the proxy
 *
 * if encrypt_mode is IO_PROXY_ENCRYPT_NONE, this does nothing and returns 0
 */
int io_proxy_init_encryption_file(io_proxy_t*, const char* pkey_file_path,
		encryption_opt encrypt_mode);

/*
 * enables compression on this io proxy
 *
 * this must be called before any read/write calls are made on the proxy
 *
 * if comp_mode is IO_PROXY_COMPRESS_NONE, this does nothing and returns 0
 */
int io_proxy_init_compression(io_proxy_t*, compression_opt comp_mode);

void io_proxy_free(io_proxy_t*);

/*
 * parses the compression string, assigning the matching enum value to opt and
 * returning 0, or returning -1 if the type is unknown
 */
int parse_compression_type(const char* comp_str, compression_opt* opt);

/*
 * parses the encryption string, assigning the matching enum value to opt and
 * returning 0, or returning -1 if the type is unknown
 */
int parse_encryption_type(const char* enc_str, encryption_opt* opt);


/*
 * writes a block of text to the io proxy, returning the number of bytes
 * successfully written, or a negative value on error
 */
ssize_t io_proxy_write(io_write_proxy_t*, const void* buf, size_t n_bytes);

/*
 * writes a single character to the io proxy, returning the character written
 * on success, or EOF on failure
 */
int32_t io_proxy_putc(io_write_proxy_t*, char c);

/*
 * prints formatted text to the io proxy, returning the number of bytes
 * successfully written, or a negative number on error
 */
int32_t io_proxy_vprintf(io_write_proxy_t*, const char* format, va_list vlist);
int32_t io_proxy_printf(io_write_proxy_t*, const char* format, ...);

/*
 * reads a block of text from the io proxy, returning the number of bytes
 * successfully read, or a negative value on error
 */
ssize_t io_proxy_read(io_read_proxy_t*, void* buf, size_t n_bytes);

/*
 * reads a single character from the io proxy, returning that character, or EOF
 * if the end of the file has been reached
 */
int32_t io_proxy_getc(io_read_proxy_t*);
int32_t io_proxy_getc_unlocked(io_read_proxy_t*);

/*
 * reads a string from the io proxy into str (of length n), stopping either when
 * n-1 characters have been read, the newline character is read, or EOF is
 * reached
 */
char* io_proxy_gets(io_read_proxy_t*, char* str, int n);

/*
 * returns the next character in the file without actually reading it, i.e. the
 * position in the file remains unchanged
 */
int32_t io_proxy_peekc_unlocked(io_read_proxy_t*);

int io_proxy_flush(io_write_proxy_t*);

/*
 * returns != 0 if there is an error, else 0 if there was no error
 */
int io_proxy_error(io_proxy_t*);

