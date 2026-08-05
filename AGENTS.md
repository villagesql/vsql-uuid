# AGENTS.md

This file provides guidance to AI coding assistants (Claude Code, Gemini Code Assist, etc.) when working with code in this repository.

**Note**: Also check `AGENTS.local.md` for additional local development instructions when present.

## Project Overview

This is a UUID extension for VillageSQL (a MySQL-compatible database) that provides a `uuid` column type plus UUID generation, validation, and introspection functions. The extension is built as a shared library packaged in a VEB (VillageSQL Extension Bundle) archive for installation.

## Build System

**Preferred:**
```bash
export VillageSQL_BUILD_DIR=/path/to/villagesql/build
./build.sh          # run from the repo root
```

**Manual equivalent:**
```bash
cmake -S . -B build -DVillageSQL_BUILD_DIR=/path/to/villagesql/build
cmake --build build
```

The build process:
1. Uses CMake with `FindVillageSQL.cmake` to locate the VillageSQL Extension SDK, selecting the highest-versioned `villagesql-extension-sdk-*` directory in the build tree
2. Compiles `src/uuid.cc` into a shared library, packaged as `lib/vsql_uuid.so`
3. Packages that library with `manifest.json` into `vsql_uuid.veb` using `VEF_CREATE_VEB()`
4. `cmake --install build` copies the VEB to `veb_output_directory` in the VillageSQL build tree

**Installing into a running server:** `veb_output_directory` is not necessarily the directory the server reads. Query the server for its `veb_dir` and copy the VEB there before `INSTALL EXTENSION vsql_uuid;`. See `TESTING.md`.

**Requirements:**
- VillageSQL build tree (specified via `VillageSQL_BUILD_DIR`)
- OpenSSL development libraries
- C++17 compiler, CMake 3.18+

**CMake Variables:**
- `VillageSQL_BUILD_DIR`: Path to VillageSQL build directory (required)
- `VillageSQL_VEB_INSTALL_DIR`: Override the VEB install destination

The SDK version must match the target server version. Compare
`villagesql_config --version` against the server's
`villagesql_server_version`; a mismatch can fail to load at install time.

## Architecture

**Core Components:**
- `src/uuid.cc` - All VDF (VillageSQL Defined Function) implementations, core UUID logic, and extension registration via `VEF_GENERATE_ENTRY_POINTS()`
- `cmake/FindVillageSQL.cmake` - CMake module to locate the VillageSQL SDK

**Extension Registration:**
The extension uses the VillageSQL Extension Framework's fluent builder API to register:
- Custom `uuid` type with encode/decode/compare functions
- All UUID functions (generation, introspection, validation, comparison)

**Available Functions:**
- **Generation**: `UUID_V1()`, `UUID_V1MC()`, `UUID_V3(ns, name)`, `UUID_V4()`, `UUID_V5(ns, name)`, `UUID_V6()`, `UUID_V7()`
- **Constants**: `UUID_NIL()`, `UUID_MAX()`, `UUID_NS_DNS()`, `UUID_NS_URL()`, `UUID_NS_OID()`, `UUID_NS_X500()`
- **Introspection**: `UUID_VERSION()`, `UUID_TIMESTAMP()`, `UUID_EPOCH()`
- **Validation**: `UUID_IS_VALID(string)`
- **Comparison**: `UUID_COMPARE()`

The `UUID_NS_*` accessors return **text**, not the `uuid` type, so they can be
passed straight into `UUID_V3`/`UUID_V5`, whose namespace parameter is a
string. Do not change those parameters to the `uuid` type without treating it
as a breaking change.

**UUID Type:**
- Custom `uuid` type with 16-byte binary storage
- Accepts three textual input forms: 32 hex chars, 36-char hyphenated, 38-char braced
- Renders as the canonical lowercase 36-character form
- Lexicographic comparison, so `PRIMARY KEY`, `UNIQUE`, `ORDER BY`, `MIN`/`MAX` all work

**UUID Versions Supported:**
- **v1**: Time-based UUIDs (host MAC address, or random multicast address via `UUID_V1MC`)
- **v3**: Name-based UUIDs using MD5 hash
- **v4**: Random UUIDs
- **v5**: Name-based UUIDs using SHA-1 hash
- **v6**: Reordered time-based UUIDs (sortable, RFC 9562)
- **v7**: Unix epoch time-based UUIDs (sortable to millisecond granularity, RFC 9562)

**Dependencies:**
- VillageSQL Extension SDK, typed C++ API only: `<villagesql/vsql.h>` and the `villagesql/vsql/` headers. Never include or reference anything under an `abi/` directory.
- OpenSSL (MD5 and SHA-1 via the EVP interface, and `RAND_bytes` for secure random data)

## Development Conventions

**Coding Style:**
The code follows the Google C++ Style Guide, with a few exceptions:
- **File Naming:** File names are lowercase with underscores (e.g., `uuid.cc`)
- **Variable Naming:** Variables are lowercase with underscores (e.g., `binary_uuid`)
- **Function Naming:** Functions are lowercase with underscores (e.g., `generate_uuid_v1`)
- **Namespace:** The core UUID helper functions are in the `uuid_funcs` namespace. Use per-symbol `using` declarations; no `using namespace` at file scope.

**Invariants that must hold in every change:**
- Every SQL entry point (each `*_impl` function, plus the type's encode and decode) is wrapped in a function-try-block that reports through `out.error(...)`. An exception must never escape into the server.
- No shared mutable state. Generators are called concurrently from multiple connections. Process-constant values use `static const` with one-time initialization; per-call state that must persist is `thread_local`. A plain mutable `static` is a data race.
- Bounds-check before every write into a result buffer. Do not assume `out.buffer()` is large enough; test `buffer().size()` first.
- Check the null flag before touching any other field of an argument.
- Nothing on the per-row path may allocate or make a syscall. The v1 node identifier is resolved once per process for exactly this reason — do not move that work back into the generator.
- Pick the failure mode by the kind of failure. `out.warning(...)` returns NULL for the row, adds a SQL warning, and lets the statement continue — this is the right choice for bad user input (a malformed `UUID_V3`/`UUID_V5` namespace). `out.error(...)` aborts the statement and is reserved for conditions that make it unsafe to continue (an RNG or digest failure, a result buffer the server sized too small, corrupt stored data). Note that in strict mode MySQL promotes a warning to an error on `INSERT`/`UPDATE`.
- `.deterministic(true)` belongs only on pure functions — same input, same output. It gates whether a function may appear in generated columns and CHECK constraints. `UUID_V3`/`UUID_V5` qualify (they are hashes of their arguments) and are marked; the time- and random-based generators do not and must never be marked.

## Testing

Full instructions, including how to install into a running server and how to
regenerate expected output, are in `TESTING.md`.

```bash
cd "$VillageSQL_BUILD_DIR"/mysql-test
VSQL_UUID_VEB=/absolute/path/to/vsql-uuid/build/vsql_uuid.veb \
  perl mysql-test-run.pl --suite=/absolute/path/to/vsql-uuid/mysql-test
```

Expected-output files in `mysql-test/r/` are generated with `--record`. Never
hand-edit one. After re-recording, read `git diff mysql-test/r/` — an
unexplained change there is a regression, not a new baseline.

## Extension Installation

The extension registers the `uuid` type and all functions automatically when loaded. The VEB package contains:
- `manifest.json` - Extension metadata
- `lib/vsql_uuid.so` - Shared library with VDF implementations

To upgrade an installed extension, use
`ALTER EXTENSION vsql_uuid VERSION '<version>' AT RESTART;` — `AT RESTART` is
mandatory, so the new build loads on the next server restart, and dependent
`uuid` columns are preserved. `UNINSTALL EXTENSION vsql_uuid` is refused while
any column in any schema still uses the type, so the uninstall/reinstall route
only works on a database with no `uuid` columns. See the Known Limitations
section of `README.md`.
