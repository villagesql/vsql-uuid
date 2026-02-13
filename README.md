![VillageSQL Logo](https://villagesql.com/assets/logo-light.svg)

# VillageSQL UUID Extension

A comprehensive UUID extension for VillageSQL Server that adds UUID generation, introspection, and comparison capabilities with support for UUID versions 1, 3, 4, 5, 6, and 7.

## Features

- **Full UUID Support**: Generate UUIDs v1 (time-based), v3 (MD5-based), v4 (random), v5 (SHA1-based), v6 (reordered time), and v7 (Unix epoch time)
- **Custom UUID Type**: Native 16-byte binary UUID storage with automatic string conversion
- **UUID Introspection**: Extract version and timestamp from existing UUIDs
- **High Performance**: Optimized C++ implementation with minimal overhead

## Installation

### Build from Source

#### Prerequisites
- VillageSQL build tree (specified via `VillageSQL_BUILD_DIR`)
- CMake 3.16 or higher
- C++17 compatible compiler
- OpenSSL development libraries (for cryptographic hash functions in v3/v5 UUID generation)

📚 **Full Documentation**: Visit [villagesql.com/docs](https://villagesql.com/docs) for comprehensive guides on building extensions, architecture details, and more.

#### Build Instructions
1. Clone the repository:
   ```bash
   git clone https://github.com/villagesql/vsql-uuid.git
   cd vsql-uuid
   ```

2. Configure CMake with required paths:

   **Linux:**
   ```bash
   mkdir -p build
   cd build
   cmake .. -DVillageSQL_BUILD_DIR=$HOME/build/villagesql
   ```

   **macOS:**
   ```bash
   mkdir -p build
   cd build
   cmake .. -DVillageSQL_BUILD_DIR=~/build/villagesql
   ```

   **Note**: `VillageSQL_BUILD_DIR` should point to your VillageSQL build directory.

3. Build the extension:
   ```bash
   make -j $(($(getconf _NPROCESSORS_ONLN) - 2))
   ```

   This creates the `vsql_uuid.veb` package in the build directory.

4. Install the VEB (optional):
   ```bash
   make install
   ```

   This copies the VEB to the directory specified by `VEB_INSTALL_DIR`. If not using `make install`, you can manually copy the VEB file to your desired location.


## Usage

After installation, the extension provides the following functions. Functions can be called with or without the extension prefix:

### UUID Generation
```sql
-- Generate UUID v4 (random)
SELECT UUID_V4();
-- Result: 550e8400-e29b-41d4-a716-446655440000

-- Generate UUID v1 (time-based)
SELECT UUID_V1();

-- Generate UUID v1 with random MAC (multicast)
SELECT UUID_V1MC();

-- Generate UUID v3 (name-based, MD5)
SELECT UUID_V3('6ba7b810-9dad-11d1-80b4-00c04fd430c8', 'example.com');

-- Generate UUID v5 (name-based, SHA1)
SELECT UUID_V5('6ba7b810-9dad-11d1-80b4-00c04fd430c8', 'example.com');

-- Generate UUID v6 (reordered time-based, sortable)
SELECT UUID_V6();

-- Generate UUID v7 (Unix epoch time-based, sortable)
SELECT UUID_V7();
```

### UUID Introspection
```sql
-- Get UUID version
SELECT UUID_VERSION('550e8400-e29b-41d4-a716-446655440000'); -- Returns 4

-- Get timestamp from v1, v6, or v7 UUID
SELECT UUID_TIMESTAMP('6ba7b810-9dad-11d1-80b4-00c04fd430c8');
-- Returns: 1998-02-04 22:13:53

-- Get Unix epoch timestamp from v1, v6, or v7 UUID
SELECT UUID_EPOCH('6ba7b810-9dad-11d1-80b4-00c04fd430c8');
-- Returns: 886630433 (Unix timestamp)

-- Returns NULL for UUIDs without timestamps (v3, v4, v5)
SELECT UUID_EPOCH('550e8400-e29b-41d4-a716-446655440000'); -- Returns NULL

-- Compare UUIDs (-1, 0, or 1)
SELECT UUID_COMPARE('550e8400-e29b-41d4-a716-446655440000',
                     '6ba7b810-9dad-11d1-80b4-00c04fd430c8');
```

### UUID Type
The extension provides a custom `UUID` type for efficient storage:
```sql
-- Create table with UUID column
CREATE TABLE users (
    id UUID PRIMARY KEY,
    name VARCHAR(100)
);

-- Insert with generated UUID
INSERT INTO users VALUES (UUID_V4(), 'John Doe');
```

## Testing

The extension includes comprehensive tests using the MySQL Test Runner (MTR) framework.

### Running Tests

**Option 1 (Default): Using installed VEB**

This method assumes you have successfully run `make install` to install the VEB to your veb_dir.

**Linux:**
```bash
cd $HOME/build/villagesql/mysql-test
perl mysql-test-run.pl --suite=/path/to/vsql-uuid/test

# Run individual test
perl mysql-test-run.pl --suite=/path/to/vsql-uuid/test uuid_basic
```

**macOS:**
```bash
cd ~/build/villagesql/mysql-test
perl mysql-test-run.pl --suite=/path/to/vsql-uuid/test

# Run individual test
perl mysql-test-run.pl --suite=/path/to/vsql-uuid/test uuid_basic
```

**Option 2: Using a specific VEB file**

Use this to test a specific VEB build without installing it first:

**Linux:**
```bash
cd $HOME/build/villagesql/mysql-test
VSQL_UUID_VEB=/path/to/vsql-uuid/build/vsql_uuid.veb \
  perl mysql-test-run.pl --suite=/path/to/vsql-uuid/test
```

**macOS:**
```bash
cd ~/build/villagesql/mysql-test
VSQL_UUID_VEB=/path/to/vsql-uuid/build/vsql_uuid.veb \
  perl mysql-test-run.pl --suite=/path/to/vsql-uuid/test
```

## Development

### Project Structure
```
vsql-uuid/
├── src/
│   └── uuid.cc              # VDF implementations, core UUID logic, and extension registration
├── cmake/
│   └── FindVillageSQL.cmake # CMake module to locate VillageSQL SDK
├── test/
│   ├── t/                   # MTR test files
│   └── r/                   # MTR expected results
├── manifest.json            # VEB package manifest
├── CMakeLists.txt           # Build configuration
└── AGENTS.md                # AI coding assistant instructions
```

### Build Targets
- `make` - Build the extension and create the `vsql_uuid.veb` package

## Reporting Bugs and Requesting Features

If you encounter a bug or have a feature request, please open an [issue](./issues) using GitHub Issues. Please provide as much detail as possible, including:

*   A clear and descriptive title.
*   A detailed description of the issue or feature request.
*   Steps to reproduce the bug (if applicable).
*   Your environment details (OS, VillageSQL version, etc.).

## License

License information can be found in the [LICENSE](./LICENSE) file.

## Contributing

VillageSQL welcomes contributions from the community. For more information, please see the [VillageSQL Contributing Guide](https://github.com/villagesql/villagesql-server/blob/main/CONTRIBUTING.md).

## Contact

We are excited you want to be part of the Village that makes VillageSQL happen. You can interact with us and the community in several ways:

+ File a [bug or issue](./issues) and we will review
+ Start a discussion in the project [discussions](./discussions)
+ Join the [Discord channel](https://discord.gg/KSr6whd3Fr)
