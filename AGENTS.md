# AGENTS.md

This file provides guidance to AI coding assistants (Claude Code, Gemini Code Assist, etc.) when working with code in this repository.

**Note**: Also check `AGENTS.local.md` for additional local development instructions when present.

## Project Overview

This is a UUID extension for VillageSQL (a MySQL-compatible database) that provides UUID generation and manipulation functions. The extension is built as a shared library (.so) packaged in a VEB (VillageSQL Extension Bundle) archive for installation.

## Build System

**Configure and Build:**
```bash
mkdir build && cd build
cmake .. -DVillageSQL_BUILD_DIR=/path/to/villagesql/build
make
```

**Install (optional):**
```bash
make install
```

The build process:
1. Uses CMake with `FindVillageSQL.cmake` to locate the VillageSQL Extension SDK
2. Compiles C++ source files into shared library `vsql-uuid.so`
3. Packages library with `manifest.json` into `vsql_uuid.veb` archive using `VEF_CREATE_VEB()`
4. Optionally installs VEB to `veb_output_directory` in the VillageSQL build tree

**Requirements:**
- VillageSQL build tree (specified via `VillageSQL_BUILD_DIR`)
- OpenSSL development libraries
- C++17 compiler

**CMake Variables:**
- `VillageSQL_BUILD_DIR`: Path to VillageSQL build directory (required)

## Architecture

**Core Components:**
- `src/uuid.cc` - All VDF (VillageSQL Defined Function) implementations, core UUID logic, and extension registration via `VEF_GENERATE_ENTRY_POINTS()`
- `cmake/FindVillageSQL.cmake` - CMake module to locate the VillageSQL SDK

**Extension Registration:**
The extension uses the VillageSQL Extension Framework's fluent builder API to register:
- Custom `uuid` type with encode/decode/compare functions
- All UUID functions (generation, introspection, comparison)

**Available Functions:**
- **Generation**: `UUID_V1()`, `UUID_V1MC()`, `UUID_V3()`, `UUID_V4()`, `UUID_V5()`, `UUID_V6()`, `UUID_V7()`
- **Introspection**: `UUID_VERSION()` - Returns UUID version number, `UUID_TIMESTAMP()` - Returns timestamp from v1/v6/v7 UUIDs
- **Comparison**: `UUID_COMPARE()` - Lexicographic UUID comparison

**UUID Type:**
- Custom `uuid` type with 16-byte binary storage
- Automatic string conversion (36-character standard format)
- Lexicographic comparison for sorting and indexing

**UUID Versions Supported:**
- **v1**: Time-based UUIDs (with MAC address or random multicast bit)
- **v3**: Name-based UUIDs using MD5 hash
- **v4**: Random UUIDs
- **v5**: Name-based UUIDs using SHA-1 hash
- **v6**: Reordered time-based UUIDs (sortable, RFC 9562)
- **v7**: Unix epoch time-based UUIDs (sortable, RFC 9562)

**Dependencies:**
- VillageSQL Extension SDK (`<villagesql/extension.h>`)
- OpenSSL (for MD5, SHA1, and secure random number generation)

## Development Conventions

**Coding Style:**
The code follows the Google C++ Style Guide, with a few exceptions:
- **File Naming:** File names are lowercase with underscores (e.g., `uuid_funcs.cc`)
- **Variable Naming:** Variables are lowercase with underscores (e.g., `binary_uuid`)
- **Function Naming:** Functions are lowercase with underscores (e.g., `generate_uuid_v1`)
- **Namespace:** The core UUID helper functions are in the `uuid_funcs` namespace

## Testing

The extension includes a comprehensive test suite using the MySQL Test Runner (MTR) framework:
- **Test Location**: `test/` directory with `.test` files and expected `.result` files

**Default: Using installed VEB**

This method assumes you have successfully run `make install` to install the VEB to your veb_dir:

```bash
cd /path/to/mysql-test
perl mysql-test-run.pl --suite=/path/to/vsql-uuid/test
```

**Alternative: Using a specific VEB file**

Use this to test a specific VEB build without installing it first:

```bash
cd /path/to/mysql-test
VSQL_UUID_VEB=/path/to/vsql-uuid/build/vsql_uuid.veb \
  perl mysql-test-run.pl --suite=/path/to/vsql-uuid/test
```

## Extension Installation

The extension registers a custom `UUID` type and all functions automatically when loaded. The VEB package contains:
- `manifest.json` - Extension metadata
- `lib/vsql-uuid.so` - Shared library with VDF implementations
