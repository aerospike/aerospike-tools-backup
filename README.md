## Aerospike Backup Tools

This is the developer documentation. For user documentation, please consult http://www.aerospike.com/docs/tools/backup.

## Building

Building the backup tools requires the source code of the Aerospike C client. Please clone it from GitHub.

    git clone https://github.com/aerospike/aerospike-client-c.

Then build the client.

    cd aerospike-client-c
    make
    cd ..

Then set the `CLIENTREPO` environment variable to point to the `aerospike-client-c` directory. The backup tools build process uses that variable to find the client code.

    export CLIENTREPO=$(pwd)/aerospike-client-c

Now clone the source code of the Aerospike backup tools from GitHub.

    git clone https://github.com/aerospike/aerospike-tools-backup

Then build the backup tools and generate the Doxygen documentation.

    cd aerospike-tools-backup
    make
    make docs

This gives you three binaries in the `bin` subdirectory -- `asbackup`, `asrestore`, and `fill` -- as well as the Doxygen HTML documentation in `docs`. Open `docs/index.html` to access the generated documentation.

In order to run the tests that come with the code, you need `asd` installed in `/usr/bin`. The tests invoke `asd` with a separate configuration file, so that your regular database environment remains untouched.

Please make sure that your `python` command is Python 2 and that you have `virtualenv` installed. By default, the tests run `asbackup` and `asrestore` under the Valgrind memory checker. If you don't have the `valgrind` command, please change `USE_VALGRIND` in `test/lib.py` to `False`. Then run the tests.

    make tests

This creates a virtual Python environment in a new subdirectory (`env`), activates it, and installs the Python packages required by the tests. Then the actual tests run.

## Backup Source Code

Let's take a quick look at the overall structure of the `asbackup` source code, at `src/backup.c`. The code does the following, starting at `main()`.

  * Parse command line options into local variables or, if they need to be passed to a worker thread later, into a `backup_config` structure.
  * Initialize an Aerospike client and connect it to the cluster to be backed up.
  * Create the counter thread, which starts at `counter_thread_func()`. That's the thread that outputs the status and counter updates during the backup, among other things.
  * When backing up to a single file (`--output-file` option, as opposed to backing up to a directory using `--directory`), create and open that backup file.
  * Populate a `backup_thread_args` structure for each node to be backed up and submit it to the `job_queue` queue. Note two things:
    - Only one of the `backup_thread_args` structures gets its `first` member set to `true`.
    - When backing up to a single file, the `shared_fd` member gets the file handle of the created backup file (and `NULL` otherwise).
  * Spawn backup worker threads, which start at `backup_thread_func()`. There's one of those for each cluster node to be backed up.
  * Wait for all backup worker threads to finish.
  * When backing up to a single file, close that file.
  * Shut down the Aerospike client.

Let's now look at what the worker threads do, starting at `backup_thread_func()`.

  * Pop a `backup_thread_args` structure off the job queue. The job queue contains exactly one of those for each thread.
  * Initialize a `per_node_context` structure. That's where all the data local to a worker thread is kept. Some of the data is initialized from the `backup_thread_args` structure. In particular, when backing up to a single file, the `fd` member of the `per_node_context` structure is initialized from the `shared_fd` member of the `backup_thread_args` structure. In that way, all backup threads share the same backup file handle.
  * When backing up to a directory, open an exclusive backup file for the worker thread by invoking `open_dir_file()`.
  * If the backup thread is the single thread that has `first` set to `true` in its `backup_thread_args` structure, store secondary index definitions by invoking `process_secondary_indexes()`, and store UDF files by invoking `process_udfs()`. So, this work is done by a single thread, and that thread is chosen by setting its `first` member to `true`.
  * All other threads wait for the chosen thread to finish its secondary index and UDF file work by invoking `wait_one_shot()`. The chosen thread signals completion by invoking `signal_one_shot()`.
  * Initiate backup of records by invoking `aerospike_scan_node()` with `scan_callback()` as the callback function that gets invoked for each record in the namespace to be backed up. From here on, all worker threads work in parallel.

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
  * Invoke `aerospike_key_put()` to store the current record in the cluster.

For more detailed information, please generate the documentation (`make docs`) and open `docs/index.html`.

## Fill Utility

`fill` is a small utility that populates a database with test data. It fills records with pseudo-random data according to record specifications and adds them to a given set in a given namespace.

### Record Specifications

A record specification defines the bins of a generated record, i.e., how many there are and what type of data they contain: a 50-character string, a 100-element list of integers, or something more deeply nested, such as a 100-element list of 50-element maps that map integer keys to 500-character string values.

The available record specifications are read from a file, `spec.txt` by default. The format of the file is slightly Lisp-like. Each record specification has the following general structure.

    (record "{spec-id}"
        {bin-count-1} {bin-type-1}
        {bin-count-2} {bin-type-2}
        ...)

This declares a record specification that can be accessed under the unique identifier `{spec-id}`. It defines a record that has `{bin-count-1}`-many bins with data of type `{bin-type-1}`, `{bin-count-2}`-many bins with data of type `{bin-type-2}`, etc.

Accordingly, the `{bin-count-x}` placeholders are just integer values. The `{bin-type-x}` placeholders, on the other hand, are a little more complex. They have to be able to describe nested data types. They have one of six forms.

| `{bin-type-x}` | Semantics |
|----------------|-----------|
| `(integer)`    | A 64-bit integer value. |
| `(double)`     | A 64-bit floating-point value |
| `(string {length})` | A string value of the given length. |
| `(list {length} {element-type})` | A list of the given length, whose elements are of the given type. This type can then again have one of these six forms. |
| `(map {size} {key-type} {value-type})` | A map of the given size, whose keys and values are of the given types. These types can then again have one of these six forms. |

Let's reconsider the above examples: a 50-character string, a 100-element list of integers, and a 100-element list of 50-element maps that map integer keys to 500-character string values. Let's specify a record that has 1, 3, and 5 bins of those types, respectively.

    (record "example"
        1 (string 50)
        3 (list 100 (integer))
        5 (list 100 (map 50 (integer) (string 500))))

### Fill Source Code

The specification file is parsed by a Ragel (http://www.colm.net/open-source/ragel/) parser. The state machine for the parser is in `src/spec.rl`. Ragel automatically generates the C parser code from this file. Not everybody has Ragel installed, so the auto-generated C file, `src/spec.c`, is included in the Git repository. If you want to re-generate `spec.c` from `spec.rl`, do the following.

    make ragel

The parser interfaces with the rest of the code via a single function, parse(). This parses the specification file into a linked list of record specifications (@ref rec_node). Each record specification points to a linked list of bin specifications (@ref bin_node), each of which, in turn, says how many bins to add to the record and with which data type. The data type is given by a tree of @ref type_node. See the documentation of spec.h and the `struct` types declared there for more information.

In its most basic form, the `fill` command could be invoked as follows, for example.

    fill test-ns test-set 1000 test-spec-1 2000 test-spec-2 3000 test-spec-3

This would add a total of 6,000 records to set `test-set` in namespace `test-ns`: 1,000 records based on `test-spec-1`, 2,000 records based on `test-spec-2`, and 3,000 records based on `test-spec-3`.

The three (count, record specification) pairs -- (1000, "test-spec-1"), (2000, "test-spec-2"), (3000, "test-spec-3") -- are parsed into a linked list of _fill jobs_ (@ref job_node). The code then iterates through this list and invokes fill() for each job.

The fill() function fires up the worker threads and then just sits there and prints progress information until the worker threads are all done.

The worker threads start at the fill_worker() function. This function generates records according to the given record specification (create_record()), generates a key (init_key()), and puts the generated record in the given set in the given namespace using the generated key. The individual bin values are created by generate(), which recurses in the case of nested data types. Please consult the documentation for fill.c for more details on the code.

The following options to `fill` are probably non-obvious.

| Option             | Effect |
|--------------------|--------|
| `-k {key-type}`    | By default, we randomly pick an integer key, a string key, or a bytes key for each record. Specifying `integer`, `string`, or `bytes` as the `{key-type}` forces a random key of the given type to be created instead. |
| `-c {tps-ceiling}` | Limits the total number of records put per second by the `fill` tool (TPS) to the given ceiling. Handy to prevent server overload. |
| `-b`               | Enables benchmark mode, which speeds up the `fill` tool. In benchmark mode we generate just one single record for a fill job and repeatedly put this same record with different keys; all records of a job thus contain identical data. Without benchmark mode, each record to be put is re-generated from scratch, which results in unique data in each record. |
| `-z`               | Enables fuzzing. Fuzzing uses random junk data for bin names, string and BLOB bin values, etc. in order to try to trip the backup file format parser. |

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
| `{data-type}`  | The data type of the indexed value: `N` = numeric, `S` = string |

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
    ["-"] [SP] ["I"] [SP] [escape({bin-name})] [SP] [{int-value}] [LF]
    ["-"] [SP] ["D"] [SP] [escape({bin-name})] [SP] [{float-value}] [LF]
    ["-"] [SP] ["S"] [SP] [escape({bin-name})] [SP] [{string-length}] [SP] [{string-data}] [LF]
    ["-"] [SP] ["B"] ["!"]? [SP] [escape({bin-name})] [SP] [{bytes-length}] [SP] [{bytes-data}] [LF]

The first form represents a `NIL`-valued bin. The remaining four forms represent an integer-valued, a double-valued, a string-valued, and a bytes-valued bin. They are completely analogous to the above four forms for an integer, a double, a string, and a bytes record key value. Accordingly, the placeholders `{int-value}`, `{float-value}`, `{string-length}`, `{string-data}`, `{bytes-length}`, and `{bytes-data}` work in exactly the same way -- just for bin values instead of key values.

| Placeholder       | Content |
|-------------------|---------|
| `{bin-name}`      | The name of the bin. |
| `{int-value}`     | The signed decimal 64-bit integer value of the bin. |
| `{float-value}`   | The decimal 64-bit floating point value of the bin, including `nan`, `+inf`, and `-inf`. |
| `{string-length}` | The length of the string value of the bin, measured in raw bytes; an unsigned decimal 32-bit value. |
| `{string-data}`   | The content of the string value of the bin: `{string-length}` raw bytes of data; not escaped, may contain NUL, etc. |
| `{bytes-length}`  | If `["!"]` present: The length of the bytes value of the bin.<br>Else: The length of the base-64 encoded bytes value of the bin.<br>In any case, an unsigned decimal 32-bit value. |
| `{bytes-data}`    | If `["!"]` present: The content of the bytes value of the bin: `{bytes-length}` raw bytes of data; not escaped, may contain NUL, etc.<br>Else: The base-64 encoded content of the bytes value of the bin: `{bytes-length}` base-64 characters. |

Actually, the above `["B"]` form is not the only way to represent bytes-valued bins. It gets a little more specific than that. There are other tokens that refer to more specific bytes values. In particular, list-valued and map-valued bins are represented as a bytes value.

| Token   | Type |
|---------|------|
| `["B"]` | Generic bytes value. |
| `["J"]` | Java bytes value. |
| `["C"]` | C# bytes value. |
| `["P"]` | Python bytes value. |
| `["R"]` | Ruby bytes value. |
| `["H"]` | PHP bytes value. |
| `["E"]` | Erlang bytes value. |
| `["M"]` | Map value, opaquely represented as a bytes value. |
| `["L"]` | List value, opaquely represented as a bytes value. |
| `["U"]` | LDT value, opaquely represented as a bytes value. Deprecated. |

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
