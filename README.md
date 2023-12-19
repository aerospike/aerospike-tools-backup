## Aerospike Backup Tools

![Build:Main](https://github.com/citrusleaf/aerospike-tools-backup/workflows/Build:Main/badge.svg)
[![codecov](https://codecov.io/gh/aerospike/aerospike-tools-backup/branch/main/graph/badge.svg)](https://codecov.io/gh/aerospike/aerospike-tools-backup)

This is the developer documentation. For user documentation, please consult http://www.aerospike.com/docs/tools/backup.

## Building

Make sure you have all dependencies installed for the Aerospike C client, Aerospike secret agent C client, and asbackup.
See https://github.com/aerospike/aerospike-client-c#build-prerequisites for more C client information.
See https://github.com/aerospike/secret-agent-client-c#building for more secret agent C client information.
Below are dependencies for asbackup only.
- openssl 3
- An event library: libuv, libevent, or libev (also used by the C client submodule)
- zstd
- aws-sdk-cpp version 1.10.55
- curl
- jansson (used by the secret-agent-client submodule)

Clone the source code of the Aerospike backup tools from GitHub.

    git clone https://github.com/aerospike/aerospike-tools-backup

Then checkout submodules and build the backup tools.

    cd aerospike-tools-backup
    git submodule update --init --recursive
    make

This gives you two binaries in the `bin` subdirectory -- `asbackup` and `asrestore`.

## Build Examples

These examples assume you have checked out and initialized the asbackup submodules
and are in the root directory of the asbackup project.

### Debian and Ubuntu (dynamic linking)

```shell
apt-get update

# Install C client dependencies...

# Install secret agent C client dependencies...

# asbackup dependencies
apt-get install build-essential libssl-dev libuv1-dev libcurl4-openssl-dev libzstd-dev libjansson-dev

# for aws-sdk-cpp build
apt-get install cmake pkg-config zlib1g-dev

# download aws sdk
git clone https://github.com/aws/aws-sdk-cpp.git
cd aws-sdk-cpp
git submodule update --init --recursive

# build aws sdk dynamic
mkdir build
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_ONLY="s3" -DBUILD_SHARED_LIBS=ON -DENABLE_TESTING=OFF -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib
make -C build

# install aws static sdk
cd build
make install
cd ../..

make EVENT_LIB=libuv
```

### Debian and Ubuntu (static linking)

```shell
apt-get update -y

# Install C client dependencies...

# Install secret agent C client dependencies...

# asbackup dependencies
apt-get install -y build-essential libssl-dev libcurl4-openssl-dev libzstd-dev libjansson-dev

# for aws-sdk-cpp build
apt-get install -y cmake pkg-config zlib1g-dev

# for libuv source build
apt-get install -y autotools-dev automake libtool

# build libuv from source since asbackup makefile expects libuv.a
# but libuv1-dev installs libuv_a.a #TODO support both or an override in the makefile
git clone https://github.com/libuv/libuv
cd libuv
sh autogen.sh
./configure
make
make install
cd ..

# install curl from source to leave out nghttp2
git clone https://github.com/curl/curl.git
cd curl
git submodule update --init --recursive

# build curl
mkdir build
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib -DBUILD_SHARED_LIBS=OFF -DBUILD_CURL_EXE=OFF
make -C build

# install curl
cd build
make install
cd ../..

# download aws sdk
git clone https://github.com/aws/aws-sdk-cpp.git
cd aws-sdk-cpp
git submodule update --init --recursive

# build aws sdk dynamic
mkdir build
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_ONLY="s3" -DBUILD_SHARED_LIBS=OFF -DENABLE_TESTING=OFF -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib -DENABLE_UNITY_BUILD=ON
make -C build

# install aws static sdk
cd build
make install
cd ../..

# Build asbackup
# Each of asbackup's dependencies have corresponding environment variables
# that are used to force static linking.
ARCH=$(uname -m)
make EVENT_LIB=libuv ZSTD_STATIC_PATH=/usr/lib/$ARCH-linux-gnu AWS_SDK_STATIC_PATH=/usr/local/lib CURL_STATIC_PATH=/usr/local/lib OPENSSL_STATIC_PATH=/usr/lib/$ARCH-linux-gnu LIBUV_STATIC_PATH=/usr/local/lib JANSSON_STATIC_PATH=/usr/lib/$ARCH-linux-gnu
```

### Red Hat Enterprise Linux or CentOS (dynamic linking)

```shell
yum update

# Install C client dependencies...

# Install secret agent C client dependencies...

# asbackup dependencies
yum groupinstall 'Development Tools'
yum install openssl-devel libcurl-devel libzstd-devel jansson-devel

# build libuv from source since the headers
# aren't in the libuv yum package
git clone https://github.com/libuv/libuv
cd libuv
sh autogen.sh
./configure
make
make install
cd ..

# for aws-sdk-cpp build
yum install cmake

# download aws sdk
git clone https://github.com/aws/aws-sdk-cpp.git
cd aws-sdk-cpp
git checkout $AWS_SDK_VERSION
git submodule update --init --recursive

# build aws sdk dynamic
mkdir build
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_ONLY="s3" -DBUILD_SHARED_LIBS=ON -DENABLE_TESTING=OFF -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib
make -C build

# install aws dynamic sdk
cd build
make install
cd ../..

make EVENT_LIB=libuv
```

### MacOS (dynamic linking)

```shell
# Install C client dependencies...

# Install secret agent C client dependencies...
# libssh2 is required for the aws-sdk-cpp on mac
brew install openssl libuv curl zstd libssh2 aws-sdk-cpp jansson
make EVENT_LIB=libuv
```

### MacOS (static linking example script)
Note: Some brew installs don't come with static libraries so source install are needed.

```shell
# Install C client dependencies...

# Install secret agent C client dependencies...

# curl and aws don't come with static objects so get those later, from source
# brew installed libssh2 currently depends on openssl 1.1.1. We source install it to link with a different openssl.
brew install libuv cmake zstd openssl

# libssh2 is required for the aws-sdk-cpp on mac
# download libssh2
git clone https://github.com/libssh2/libssh2.git
cd libssh2
git submodule update --init --recursive

# build libssh2
mkdir build_static
cd build_static
cmake -DOPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl/ -DCMAKE_BUILD_TYPE=Release ..
cmake --build .

# install libssh2
make install
cd ../..

# downlad curl
git clone https://github.com/curl/curl.git
cd curl
git submodule update --init --recursive

# build curl
mkdir build
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib -DBUILD_SHARED_LIBS=OFF -DBUILD_CURL_EXE=OFF -DOPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl OPENSSL_USE_STATIC_LIBS=TRUE -DHTTP_ONLY=ON
make -C build

# install curl
cd build
make install
cd ../..

# download aws sdk
git clone https://github.com/aws/aws-sdk-cpp.git
cd aws-sdk-cpp
git submodule update --init --recursive

# build aws sdk static
mkdir build_static
cmake -S . -B build_static -DOPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl/ -DCMAKE_BUILD_TYPE=Release -DBUILD_ONLY="s3" -DBUILD_SHARED_LIBS=OFF -DENABLE_TESTING=OFF -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib
make -C build_static

# install aws static sdk
cd build_static
make install
cd ../..

# build asbackup
make EVENT_LIB=libuv ZSTD_STATIC_PATH=/opt/homebrew/lib AWS_SDK_STATIC_PATH=/usr/local/lib CURL_STATIC_PATH=/usr/local/lib OPENSSL_STATIC_PATH=/opt/homebrew/opt/openssl/lib LIBSSH2_STATIC_PATH=/usr/local/lib LIBUV_STATIC_PATH=/opt/homebrew/lib JANSSON_STATIC_PATH=/opt/homebrew/lib
```

## Tests

In order to run the tests that come with the code, you need `docker` installed. The tests spin up an Aerospike Cluster using docker containers for each node.

Please make sure that you have Python 3, `virtualenv`, and optionally `valgrind` installed. By default, the tests run `asbackup` and `asrestore` under the Valgrind memory checker. If you don't have the `valgrind` command, please change `USE_VALGRIND` in `test/lib.py` to `False`. Then run the tests.

    make test

This creates a virtual Python environment in a new subdirectory (`env`), activates it, and installs the Python packages required by the tests. Then the actual tests run.

## Backup Source Code

Let's take a quick look at the overall structure of the `asbackup` source code, at `src/backup.c`. The code does the following, starting at `backup_main()`.

  * Parse command line options into a `backup_config` struct with `backup_config_init`.
  * Call `run_backup`, which first initializes all run status variables and an Aerospike client into a `backup_status` struct with `backup_status_init`.
  * If only zero or one partition ranges are given, evenly divide the partition range into `--parallel` individual filters. This is done because each partition filter/range is a single backup job and cannot be parallelized.
  * If we are resuming a backup run, load the backup state into the `backup_status` struct and narrow the partition filters (i.e. have them begin from where they left off in the interrupted run).
  * If backing up to a single file (`--output-file` option, as opposed to backing up to a directory using `--directory`), create and open that backup file.
    - If this is a resumed run, reopen the shared file from the backup state.
    - Otherwise, run a backup estimate, calculate a 99.9% confidence estimate on the size of the final backup file, and open a file with that estimated size.
  * If running a backup estimate, open a file writing to `\dev\null`.
  * If backing up to a directory, initialize the file queue, scan the backup directory to make sure no files exist within it with an `.asb` extension, or if they do and `--remove-files` is set, delete them.
    - If this is a resumed run, reopen all files from the backup state and push them to the file queue.
  * If this is a resumable run (i.e. not an estimate), generate the path to be used for a backup state if we end up needing to make one.
  * Create the counter thread, which starts at `counter_thread_func()`. That's the thread that outputs the status and counter updates during the backup, among other things.
  * Spawn `--parallel` backup worker threads, which start at `backup_thread_func()`.
  * Wait for all backup worker threads to finish.
  * If running an estimate, display the estimate status.
  * If backing up to a directory, iterate over all files in the file queue.
    - If not saving the backup state (i.e. no error has happened), flush the file and close it.
    - If saving the backup state, place the backup file in the backup state struct.
    - If aborting the backup, close the file.
  * If backing up to a single file and saving the backup state, place that file in the backup state struct.
  * If saving the backup state (no matter what mode we're running in), go through all jobs still in the job queue and save them to the backup state.
  * Go through all completed backup jobs and save them to the backup state (if we are saving the backup state).
  * Join the counter thread.
  * If not saving the backup state, free the shared backup file if it exists.
  * Save the backup state if one was created.
  * Shut down the Aerospike client.

Let's now look at what the worker threads do, starting at `backup_thread_func()`.

  * Pop a `backup_thread_args` structure off the job queue.
  * Initialize a `backup_job_context` structure. That's where all the data local to a worker thread is kept. Some of the data is initialized from the `backup_thread_args` structure. In particular, when backing up to a single file, the `fd` member of the `backup_job_context` structure is initialized from the `shared_fd` member of the `backup_thread_args` structure. In that way, all backup threads share the same backup file handle.
  * When backing up to a directory, open an exclusive backup file for the worker thread by invoking `open_dir_file()`. A backup file may be taken from the file queue if it isn't empty, or if it is empty, a new backup file is created.
  * If the backup thread is the single thread that has `first` set to `true` in its `backup_thread_args` structure, store secondary index definitions by invoking `process_secondary_indexes()`, and store UDF files by invoking `process_udfs()`. So, this work is done by a single thread, and that thread is chosen by setting its `first` member to `true`.
  * All other threads wait for the chosen thread to finish its secondary index and UDF file work by invoking `wait_one_shot()`. The chosen thread signals completion by invoking `signal_one_shot()`.
  * Initiate backup of records by invoking `aerospike_scan_partitions()` with `scan_callback()` as the callback function that gets invoked for each record in the namespace to be backed up. From here on, all worker threads work in parallel.
  * If, after completing the scan, the backup file is not full (i.e. less than `--file-limit` MB in size), place the backup file on the file queue to be reused by another backup job.

Let's now look at what the callback function, `scan_callback()`, does.

  * When backing up to a directory and the current backup file of a worker thread has grown beyond its maximal size, switch to a new backup file by invoking `close_dir_file()` for the old and `open_dir_file()` for the new backup file.
  * When backing up to a single file, acquire the file lock by invoking `safe_lock()`. As all worker threads share the same backup file, we can only allow one thread to write at a time.
  * Invoke the `put_record()` function of the backup encoder for the current record. The encoder implements the backup file format by taking record information and serializing it to the backup file. Its code is in `src/enc_text.c`, its interface in `include/enc_text.h`. Besides `put_record()`, the interface contains `put_secondary_index()` and `put_udf_file()`, which are used to store secondary index definitions and UDF files in a backup file.
  * When backing up to a single file, release the file lock.

## Restore Source Code

Let's now take a quick look at the overall structure of the `asrestore` source code, at `src/restore.c`. The code does the following, starting at `main()`.

  * Parse command line options into local variables or, if they need to be passed to a worker thread later, into a `restore_config` structure.
  * Initialize an Aerospike client and connect it to the cluster to be restored.
  * Create the counter thread, which starts at `counter_thread_func()`. That's the thread that outputs the status and counter updates during the restore, among other things.
  * When restoring from a directory (`--directory` option, as opposed to restoring from a single file using `--input-file`), collect all backup files from that directory. Then go through the backup files, find the one that has the secondary index definitions and UDF files in it, and parse that information by invoking `get_indexes_and_udfs()`. Then populate one `restore_thread_args` structure for each backup file and submit it to the `job_queue` queue.
  * When restoring from a single file, open that file and populate the `shared_fd` member of the `restore_thread_args` structure with the file handle of that shared backup file. Then parse the secondary index definitions and UDF files from that file by invoking `get_indexes_and_udfs()`. Finally, submit one `restore_thread_args` structure for each worker thread to the job queue.
  * Restore the UDF files to the cluster by invoking `restore_udfs()`.
  * When secondary indexes are to be restored before any records, invoke `restore_indexes()` to create them.
  * Create the restore worker threads, which start at `restore_thread_func()`.
  * Wait for all restore worker threads to finish.
  * When secondary indexes are to be restore after all records, invoke `restore_indexes()` to create them.
  * When restoring from a single file, close that file.
  * Shut down the Aerospike client.

Let's now look at what the worker threads do, starting at `restore_thread_func()`. The code is pretty similar in structure to its counterpart in `asbackup`.

  * Pop a `restore_thread_args` structure off the job queue.
  * Initialize a `per_thread_context` structure. That's where all the data local to a worker thread is kept. Some of the data is initialized from the `restore_thread_args` structure. In particular, when restoring from a single file, the `fd` member of the `per_thread_context` structure is initialized from the `shared_fd` member of the `restore_thread_args` structure. In that way, all restore threads share the same backup file handle.
  * When restoring from a directory, open an exclusive backup file for the worker thread by invoking `open_file()`.
  * Set up the write policy, depending on the command line arguments given by the user.
  * When restoring from a single file, acquire the file lock by invoking `safe_lock()`. As all worker threads read from the same backup file, we can only allow one thread to read at a time.
  * Invoke the `parse()` function of the backup decoder to read the next record. The decoder is the counterpart to the encoder in `asbackup`. It implements the backup file format by deserializing record information from the the backup file. Its code is in `src/dec_text.c`, its interface in `include/dec_text.h`.
  * When backing up to a single file, release the file lock.
  * Call `record_uploader_put` to asynchronously upload the record in batches.

## Backup File Format

Currently, there is only a single, text-based backup file format, which provides compatibility with previous versions of Aerospike. However, backup file formats are pluggable and a binary format could be supported in the future.

Regardless of the format, any backup file starts with a header line that identifies it as an Aerospike backup file and specifies the version of the backup file format.

    ["Version"] [SP] ["3.1"] [LF]

Let's use the above to agree on a few things regarding notation.

  * `["Version"]` is a 7-character string literal that consists of the letters `V`, `e`, `r`, `s`, `i`, `o`, and `n`. Likewise, `["3.1"]` is a 3-character string literal.

  * `[SP]` is a single space character (ASCII code 32).

  * `[LF]` is a single line feed character (ASCII code 10).

Note that the backup file format is pretty strict. When the specification says `[SP]`, it really means a single space character: not more than one, no tabs, etc. Also, `[LF]` really is a single line feed character: no carriage returns, not more than one (i.e., no empty lines), etc. Maybe it's helpful to look at the text-based format as a binary format that just happens to be readable by humans.

### Meta Data Section

The header line is always followed by zero or more lines that contain meta information about the backup file ("meta data section"). These lines always start with a `["#"] [SP]` prefix. Currently, there are two different meta information lines.

    ["#"] [SP] ["namespace"] [SP] [escape({namespace})] [LF]
    ["#"] [SP] ["first-file"] [LF]

  * The first line specifies the namespace from which this backup file was created.

  * The second line marks this backup file as the first in a set of backup files. We discussed above what exactly this means and why it is important.

We also introduced a new notation, `escape(...)`. Technically, a namespace identifier can contain space characters or line feeds. As the backup file format uses spaces and line feeds as token separators, they need to be escaped when they appear inside a token. We escape a token by adding a backslash ("\\") character before any spaces, line feeds, and backslashes in the token. And that's what `escape(...)` means.

Escaping naively works on bytes. It thus works without having to know about character encodings. If we have a UTF-8 string that contains a byte with value 32, this byte will be escaped regardless of whether it is an actual space character or part of the encoding of a Unicode code point.

We also introduced placeholders into the notation, which represent dynamic data. `{namespace}` is a placeholder for, and thus replaced by, the namespace that the backup file belongs to.

For a namespace `Name Space`, the meta data line would look like this.

    ["#"] [SP] ["namespace"] [SP] ["Name\ Space"] [LF]

In general, any byte value is allowed in the dynamic data represented by a placeholder. The exception to that are placeholders that are passed to `escape(...)`.  As a general rule of thumb, escaped data may not contain NUL bytes. This is due to the design of the Aerospike C client API, which, for developer convenience, uses NUL-terminated C strings for things like namespace, set, or index names. (Not for bin values, though. Those may very well contain NUL bytes and, in line with the rule of thumb, aren't escaped. See below.)

### Global Section

The meta data section is always followed by zero or more lines that contain global cluster data, i.e., data that pertains to all nodes in the cluster ("global section"). This data currently encompasses secondary indexes and UDF files.

Lines in the global section always start with a `["*"] [SP]` prefix. Let's first look at lines that describe secondary indexes.

    ["*"] [SP] [escape({namespace})] [SP] [escape({set})] [SP] [escape({name})] [SP]
               [{index-type}] [SP] ["1"] [SP] [escape({path})] [SP] [{data-type}] [LF]

Let's look at the placeholders, there are quite a few.

| Placeholder    | Content |
|----------------|---------|
| `{namespace}`  | The namespace that the index applies to. |
| `{set}`        | The set that the index applies to. Note that this can be empty, i.e., a zero-length string, as indexes do not necessarily have to be associated with a set. |
| `{name}`       | The name of the index. |
| `{index-type}` | The type of index: `N` = index on bins, `L` = index on list elements, `K` = index on map keys, `V` = index on map values |
| `{path}`       | The bin name |
| `{data-type}`  | The data type of the indexed value: `N` = numeric, `S` = string, `G` = geo2dsphere, `B` = bytes/blob, `I` = invalid |

The `["1"]` token is actually the number of values covered by the index. This is for future extensibility, i.e., for composite indexes that span more than one value. Right now, this token is always `["1"]`, though.

Let's now look at how UDF files are represented in the global section.

    ["*"] [SP] [{type}] [SP] [escape({name})] [SP] [{length}] [SP] [{content}] [LF]

Here's what the placeholders stand for.

| Placeholder | Content |
|-------------|---------|
| `{type}`    | The type of the UDF file. Currently always `L` for Lua. |
| `{name}`    | The file name of the UDF file. |
| `{length}`  | The length of the UDF file, which is a decimal unsigned 32-bit value. |
| `{content}` | The content of the UDF file: `{length}` raw bytes of data. The UDF file is simply copied to the backup file. As we know the length of the UDF file, no escaping is required. Also, the UDF file will most likely contain line feeds, so this "line" will actually span multiple lines in the backup file. |

### Records Section

The global section is followed by zero or more records. Each record starts with a multi-line header. Record header lines always start with a `["+"] [SP]` prefix. They have to appear in the given order. Two of these lines are optional, though.

The first line is optional. It is only present, if the actual value of the key -- as opposed to just the key digest -- was stored with the record. If it is present, it has one of the following four forms, depending on whether the key value is an integer, a double, a string, or a bytes value.

    ["+"] [SP] ["k"] [SP] ["I"] [SP] [{int-value}] [LF]
    ["+"] [SP] ["k"] [SP] ["D"] [SP] [{float-value}] [LF]
    ["+"] [SP] ["k"] [SP] ["S"] [SP] [{string-length}] [SP] [{string-data}] [LF]
    ["+"] [SP] ["k"] [SP] ["B"] ["!"]? [SP] [{bytes-length}] [SP] [{bytes-data}] [LF]

Note that we introduced one last notation, `[...]?`, which indicates that a token is optional. For bytes-valued keys, `["B"]` can thus optionally be followed by `["!"]`.

Here's what the placeholders in the above four forms mean.

| Placeholder       | Content |
|-------------------|---------|
| `{int-value}`     | The signed decimal 64-bit integer value of the key. |
| `{float-value}`   | The decimal 64-bit floating point value of the key, including `nan`, `+inf`, and `-inf`. |
| `{string-length}` | The length of the string value of the key, measured in raw bytes; an unsigned decimal 32-bit value. |
| `{string-data}`   | The content of the string value of the key: `{string-length}` raw bytes of data; not escaped, may contain NUL, etc. |
| `{bytes-length}`  | If `["!"]` present: The length of the bytes value of the key.<br>Else: The length of the base-64 encoded bytes value of the key.<br>In any case, an unsigned decimal 32-bit value. |
| `{bytes-data}`    | If `["!"]` present: The content of the bytes value of the key: `{bytes-length}` raw bytes of data; not escaped, may contain NUL, etc.<br>Else: The base-64 encoded content of the bytes value of the key: `{bytes-length}` base-64 characters. |

The next two lines of the record header specify the namespace of the record and its key digest and look like this.

    ["+"] [SP] ["n"] [SP] [escape({namespace})] [LF]
    ["+"] [SP] ["d"] [SP] [{digest}] [LF]

`{namespace}` is the namespace of the record, `{digest}` is its base-64 encoded key digest.

The next line is optional again. It specifies the set of the record.

    ["+"] [SP] ["s"] [SP] [escape({set})] [LF]

`{set}` is the set of the record.

The remainder of the record header specifies the generation count, the expiration time, and the bin count of the record. It looks as follows.

    ["+"] [SP] ["g"] [SP] [{gen-count}] [LF]
    ["+"] [SP] ["t"] [SP] [{expiration}] [LF]
    ["+"] [SP] ["b"] [SP] [{bin-count}] [LF]

Here's what the above placeholders stand for.

| Placeholder    | Content |
|----------------|---------|
| `{gen-count}`  | The record generation count. An unsigned 16-bit decimal integer value. |
| `{expiration}` | The record expiration time in seconds since the Aerospike epoch (2010-01-01 00:00:00 UTC). An unsigned decimal 32-bit integer value. |
| `{bin-count}`  | The number of bins in the record. An unsigned decimal 16-bit integer value. |

The record header lines are followed by `{bin-count}`-many lines of bin data. Each bin data line starts with a `["-"] [SP]` prefix. Depending on the bin data type, a bin data line can generally have one of the following five forms.

    ["-"] [SP] ["N"] [SP] [escape({bin-name})]
    ["-"] [SP] ["Z"] [SP] [escape({bin-name})] [SP] [{bool-value}] [LF]
    ["-"] [SP] ["I"] [SP] [escape({bin-name})] [SP] [{int-value}] [LF]
    ["-"] [SP] ["D"] [SP] [escape({bin-name})] [SP] [{float-value}] [LF]
    ["-"] [SP] ["S"] [SP] [escape({bin-name})] [SP] [{string-length}] [SP] [{string-data}] [LF]
    ["-"] [SP] ["B"] ["!"]? [SP] [escape({bin-name})] [SP] [{bytes-length}] [SP] [{bytes-data}] [LF]

The first form represents a `NIL`-valued bin. The remaining four forms represent an integer-valued, a double-valued, a string-valued, and a bytes-valued bin. They are completely analogous to the above four forms for an integer, a double, a string, and a bytes record key value. Accordingly, the placeholders `{int-value}`, `{float-value}`, `{string-length}`, `{string-data}`, `{bytes-length}`, and `{bytes-data}` work in exactly the same way -- just for bin values instead of key values.

| Placeholder       | Content |
|-------------------|---------|
| `{bin-name}`      | The name of the bin. |
| `{bool-value}`    | The boolean value of the bin. |
| `{int-value}`     | The signed decimal 64-bit integer value of the bin. |
| `{float-value}`   | The decimal 64-bit floating point value of the bin, including `nan`, `+inf`, and `-inf`. |
| `{string-length}` | The length of the string value of the bin, measured in raw bytes; an unsigned decimal 32-bit value. |
| `{string-data}`   | The content of the string value of the bin: `{string-length}` raw bytes of data; not escaped, may contain NUL, etc. |
| `{bytes-length}`  | If `["!"]` present: The length of the bytes value of the bin.<br>Else: The length of the base-64 encoded bytes value of the bin.<br>In any case, an unsigned decimal 32-bit value. |
| `{bytes-data}`    | If `["!"]` present: The content of the bytes value of the bin: `{bytes-length}` raw bytes of data; not escaped, may contain NUL, etc.<br>Else: The base-64 encoded content of the bytes value of the bin: `{bytes-length}` base-64 characters. |

Actually, the above `["B"]` form is not the only way to represent bytes-valued bins. It gets a little more specific than that. There are other tokens that refer to more specific bytes values. In particular, list-valued and map-valued bins are represented as a bytes value.

| Token   | Type                                                          |
|---------|---------------------------------------------------------------|
| `["B"]` | Generic bytes value.                                          |
| `["J"]` | Java bytes value.                                             |
| `["C"]` | C# bytes value.                                               |
| `["P"]` | Python bytes value.                                           |
| `["R"]` | Ruby bytes value.                                             |
| `["H"]` | PHP bytes value.                                              |
| `["E"]` | Erlang bytes value.                                           |
| `["Y"]` | HyperLogLog, opaquely represented as a bytes value.           |
| `["M"]` | Map value, opaquely represented as a bytes value.             |
| `["L"]` | List value, opaquely represented as a bytes value.            |

### Sample Backup File

The following backup file contains two secondary indexes, a UDF file, and a record. The two empty lines stem from the UDF file, which contains two line feeds.

    Version 3.1
    # namespace test
    # first-file
    * i test test-set int-index N 1 int-bin N
    * i test test-set string-index N 1 string-bin S
    * u L test.lua 27 -- just an empty Lua file


    + n test
    + d q+LsiGs1gD9duJDbzQSXytajtCY=
    + s test-set
    + g 1
    + t 0
    + b 2
    - I int-bin 12345
    - S string-bin 5 abcde

In greater detail:

  * The backup was taken from namespace `test` and set `test-set`.

  * The record never expires and it has two bins: an integer bin, `int-bin`, and a string bin, `string-bin`, with values `12345` and `"abcde"`, respectively.

  * The secondary indexes are `int-index` for the integer bin and `string-index` for the string bin.

  * The UDF file is `test.lua` and contains 27 bytes.

Let's also look at the corresponding hex dump for a little more insight regarding the UDF file and its line feeds.

    0000: 5665 7273 696f 6e20 332e 310a 2320 6e61  Version 3.1.# na
    0010: 6d65 7370 6163 6520 7465 7374 0a23 2066  mespace test.# f
    0020: 6972 7374 2d66 696c 650a 2a20 6920 7465  irst-file.* i te
    0030: 7374 2074 6573 742d 7365 7420 696e 742d  st test-set int-
    0040: 696e 6465 7820 4e20 3120 696e 742d 6269  index N 1 int-bi
    0050: 6e20 4e0a 2a20 6920 7465 7374 2074 6573  n N.* i test tes
    0060: 742d 7365 7420 7374 7269 6e67 2d69 6e64  t-set string-ind
    0070: 6578 204e 2031 2073 7472 696e 672d 6269  ex N 1 string-bi
    0080: 6e20 530a 2a20 7520 4c20 7465 7374 2e6c  n S.* u L test.l
    0090: 7561 2032 3720 2d2d 206a 7573 7420 616e  ua 27 -- just an
    00a0: 2065 6d70 7479 204c 7561 2066 696c 650a   empty Lua file.
    00b0: 0a0a 2b20 6e20 7465 7374 0a2b 2064 2071  ..+ n test.+ d q
    00c0: 2b4c 7369 4773 3167 4439 6475 4a44 627a  +LsiGs1gD9duJDbz
    00d0: 5153 5879 7461 6a74 4359 3d0a 2b20 7320  QSXytajtCY=.+ s
    00e0: 7465 7374 2d73 6574 0a2b 2067 2031 0a2b  test-set.+ g 1.+
    00f0: 2074 2030 0a2b 2062 2032 0a2d 2049 2069   t 0.+ b 2.- I i
    0100: 6e74 2d62 696e 2031 3233 3435 0a2d 2053  nt-bin 12345.- S
    0110: 2073 7472 696e 672d 6269 6e20 3520 6162   string-bin 5 ab
    0120: 6364 650a                                cde.

The content of the Lua file consists of the 27 bytes at offsets 0x096 through 0x0b0. The line feed at 0xb0 still belongs to the Lua file, the line feed at 0xb1 is the line feed dictated by the backup file format.
