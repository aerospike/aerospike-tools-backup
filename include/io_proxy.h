/*
 * Aerospike IO Proxy
 *
 * Copyright (c) 2021-2022 Aerospike, Inc. All rights reserved.
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

#ifdef __cplusplus
extern "C" {
#endif

//==========================================================
// Includes.
//

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <openssl/aes.h>
#include <zstd.h>

#include <file_proxy.h>

 
//==========================================================
// Typedefs & Constants.
//

/*
 * number of encrypt blocks to buffer (to make one large encrypt call rather
 * than many small ones)
 */
#define N_BUFFERED_BLOCKS 256

/*
 * the default size to make the io_proxy buffer when not using compression or
 * encryption
 */
#define IO_PROXY_DEFAULT_BUFFER_SIZE \
	(N_BUFFERED_BLOCKS * AES_BLOCK_SIZE)

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
 * indicates that the io proxy should buffer writes to the file even if no
 * compression/encryption is being done
 */
#define IO_PROXY_ALWAYS_BUFFER 0x40

/*
 * the size in bytes of the buffer used by io_proxy_printf
 */
#define IO_PROXY_PRINTF_BUFFER_SIZE 1024

/*
 * Indicates that the io proxy was loaded from a file and should be
 * deserialized. If encryption is enabled,
 */
#define IO_PROXY_DESERIALIZE 0x80

/*
 * Flags that must be set after an io proxy is deserialized from a file. The
 * rest are set automatically
 */
#define IO_PROXY_INIT_FLAGS \
	(IO_PROXY_COMPRESS_MASK | IO_PROXY_ENCRYPT_MASK | IO_PROXY_ALWAYS_BUFFER)


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
	file_proxy_t file;

	consumer_buffer_t buffer;

	// write_proxy: the total number of bytes written to the file, after compression
	// read_proxy: the total number of bytes read from the file
	uint64_t byte_cnt;

	union {
		// for write_proxy: the total number of uncomrpessed bytes that have
		// passed through io->buffer
		uint64_t raw_byte_cnt;

		// for read_proxy: the total number of compressed bytes that have passed
		// through all buffers (i.e. have already been read and are no longer
		// sitting in any buffer)
		uint64_t parsed_byte_cnt;
	};

	// global offset of this buffer in the file being written to, modulo
	// AES_BLOCK_SIZE
	// used for alignment with encryption, will always be 0 if encryption is off
	uint32_t num;

	// where the option flags are stored
	uint8_t flags;
	// only used when deserializing an io_proxy from a file, compared against
	// flags when being fully initialized to verify that they match exactly
	// (otherwise initialization was done incorrectly)
	uint8_t deserialized_flags;
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


/*
 * The struct used to serialize an io_proxy to a file, only containing data
 * necessary to fully reconstruct the io_proxy.
 */
typedef struct io_proxy_serial_s {
	uint64_t byte_cnt;

	union {
		uint64_t raw_byte_cnt;
		uint64_t parsed_byte_cnt;
	};

	uint32_t num;
	uint8_t flags;

	/*
	 * The current value of the IV.
	 */
	uint8_t iv[AES_BLOCK_SIZE];
} io_proxy_serial_t;


//==========================================================
// Public API.
//

/*
 * initializes an encryption key with the provided raw data
 */
void encryption_key_init(encryption_key_t*, uint8_t* pkey_data, uint64_t len);

/*
 * Copies the src encryption key into dst, initializing dst.
 */
void encryption_key_clone(encryption_key_t* dst, const encryption_key_t* src);

/*
 * reads a private key from the given file into the pkey buffer and
 * initializes/populates the key passed
 */
int io_proxy_read_private_key_file(const char* pkey_file_path,
		encryption_key_t* key);

void encryption_key_free(encryption_key_t*);


/*
 * initiazes io read/write proxies wrapping a file. These functions by
 * default set the proxies with encryption and compression disabled
 *
 * max_file_size is the max expected file size of the file
 *
 * returns 0 on success and < 0 on failure
 */
int io_write_proxy_init(io_write_proxy_t*, const char* file_path,
		uint64_t max_file_size);
int io_read_proxy_init(io_read_proxy_t*, const char* file_path);

/*
 * Fully initializes the io proxy (must be called after encryption/compression
 * have been set up).
 */
int io_proxy_initialize(io_write_proxy_t*);

/*
 * Serializes an io_proxy into file, returning 0 on success and < 0 on failure.
 */
int io_proxy_serialize(io_proxy_t*, file_proxy_t* dst);

/*
 * Deserializes an io_proxy from the file, fully initializing the io_proxy.
 *
 * src is where the serialized io_proxy is read from.
 *
 * Returns 0 on success and < 0 on failure.
 */
int io_proxy_deserialize(io_proxy_t*, file_proxy_t* src);

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

/*
 * Sets the compression level to use. May only be called on proxies opened in
 * write mode with compression enabled (after the call to
 * io_proxy_init_compression).
 *
 * Returns non-zero on error, 0 on success.
 */
int io_proxy_set_compression_level(io_proxy_t*, int32_t compression_level);

/*
 * Closes the io_proxy and frees resources associated with it. If this returns
 * non-zero, then the io_proxy is still in a valid state and hasn't been closed.
 *
 * Returns 0 on success and EOF on error.
 *
 * Mode is the mode in which to free the io proxy. One of the FILE_PROXY_*
 * modes (see file_proxy_close2)
 */
int io_proxy_close(io_proxy_t*);
int io_proxy_close2(io_proxy_t*, uint8_t mode);

__attribute__((pure)) bool io_proxy_is_writer(io_proxy_t* io);
__attribute__((pure)) bool io_proxy_is_reader(io_proxy_t* io);

/*
 * returns true if the io_proxy has compression enabled
 */
__attribute__((pure)) bool io_proxy_do_compress(const io_proxy_t* io);

/*
 * returns true if the io_proxy has encryption enabled
 */
__attribute__((pure)) bool io_proxy_do_encrypt(const io_proxy_t* io);

/*
 * returns the file path used to open this io proxy
 */
const char* io_proxy_file_path(const io_proxy_t* io);

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
 * returns the number of bytes that have been written to the file, excluding
 * those that are still in the buffers
 */
int64_t io_write_proxy_bytes_written(const io_write_proxy_t*);

/*
 * returns the raw number of uncomrpessed bytes that have been passed to the
 * file
 */
int64_t io_write_proxy_absolute_pos(const io_write_proxy_t*);

/*
 * returns an estimate of the number of compressed bytes read from the file
 */
int64_t io_read_proxy_estimate_pos(const io_read_proxy_t*);

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

/*
 * flushes the internal buffers of the io proxy
 */
int io_proxy_flush(io_write_proxy_t*);

/*
 * returns != 0 if there is an error, else 0 if there was no error
 */
int io_proxy_error(io_proxy_t*);

#ifdef __cplusplus
}
#endif

