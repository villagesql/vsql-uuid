![VillageSQL Logo](https://villagesql.com/assets/logo-light.svg)

# VillageSQL UUID Extension

A UUID extension for VillageSQL Server providing a native 16-byte `uuid`
column type plus generation, validation, and introspection functions for UUID
versions 1, 3, 4, 5, 6, and 7 (RFC 9562).

## Features

- **Native `uuid` type** — 16 bytes of storage per value, not 36, with
  automatic conversion to and from text
- **Six UUID versions** — v1 and v1mc (time-based), v3 (MD5), v4 (random),
  v5 (SHA-1), v6 (reordered time), v7 (Unix epoch time)
- **RFC 9562 namespace constants** — `UUID_NS_DNS()` and friends, so name-based
  UUIDs need no hard-coded namespace literals
- **Introspection** — read the version and embedded timestamp back out of a
  stored UUID
- **Sortable and indexable** — lexicographic comparison means `PRIMARY KEY`,
  `UNIQUE`, `ORDER BY`, `MIN`, and `MAX` all behave as expected

## Building

**Prerequisites**

- VillageSQL build tree (specified via `VillageSQL_BUILD_DIR`)
- CMake 3.18 or higher
- C++17 compatible compiler
- OpenSSL development libraries (MD5 and SHA-1 for v3/v5, secure random bytes
  for v4/v7)

📚 **Full Documentation**: Visit [villagesql.com/docs](https://villagesql.com/docs)
for comprehensive guides on building extensions, architecture details, and more.

**Linux and macOS**

```bash
git clone https://github.com/villagesql/vsql-uuid.git
cd vsql-uuid
export VillageSQL_BUILD_DIR=$HOME/build/villagesql
./build.sh
```

This produces `build/vsql_uuid.veb`.

The equivalent without the script:

```bash
cmake -S . -B build -DVillageSQL_BUILD_DIR="$VillageSQL_BUILD_DIR"
cmake --build build
```

The SDK version must match your server version. If `INSTALL EXTENSION` fails
with a protocol or ABI error, compare the two:

```bash
"$VillageSQL_BUILD_DIR"/villagesql-extension-sdk-*/bin/villagesql_config --version
mysql -u root -p -e "SHOW VARIABLES LIKE 'villagesql_server_version';"
```

## Installing

The server loads VEB packages from the directory named by its `veb_dir`
variable. Ask the server for that path rather than assuming it — `cmake
--install` writes to the SDK's `veb_output_directory`, which on a development
build is a different directory:

```bash
mysql -u root -p -e "SHOW VARIABLES LIKE 'veb_dir';"
cp build/vsql_uuid.veb /path/reported/by/veb_dir/
mysql -u root -p -e "INSTALL EXTENSION vsql_uuid;"
```

The `uuid` type and all functions register automatically on load. Function
names may be used bare or qualified as `vsql_uuid.UUID_V4()`.

### Upgrading an existing installation

Copy the new VEB into `veb_dir` and point the server at its version. Dependent
`uuid` columns are preserved, so nothing needs to be dropped — but the swap
happens on the next restart, which the grammar makes mandatory:

```bash
cp build/vsql_uuid.veb /path/reported/by/veb_dir/
mysql -u root -p -e "ALTER EXTENSION vsql_uuid VERSION '0.0.6' AT RESTART;"
# then restart the server
```

The version must match a VEB the server can find — either
`vsql_uuid-<version>.veb` or the unversioned `vsql_uuid.veb` whose manifest
declares that version. Otherwise you get
`ERROR 3219: VEB file not found: vsql_uuid-<version>.veb`.

The uninstall/reinstall route works only on a database with no `uuid` columns
at all, since `UNINSTALL` is refused while any column depends on the type:

```bash
mysql -u root -p -e "UNINSTALL EXTENSION vsql_uuid;"
rm -rf /path/reported/by/veb_dir/_expanded/vsql_uuid
cp build/vsql_uuid.veb /path/reported/by/veb_dir/
mysql -u root -p -e "INSTALL EXTENSION vsql_uuid;"
```

## Usage

```sql
CREATE TABLE users (
    id   UUID PRIMARY KEY,
    name VARCHAR(100)
);

INSERT INTO users VALUES (UUID_V7(), 'Ada Lovelace');

SELECT id, name, UUID_VERSION(id) AS ver, UUID_TIMESTAMP(id) AS created
FROM users;
```

### Generation

```sql
SELECT UUID_V4();     -- random
SELECT UUID_V7();     -- Unix-epoch time-based, sorts by creation time
SELECT UUID_V6();     -- reordered time-based, sorts by creation time
SELECT UUID_V1();     -- time-based, embeds the host MAC address
SELECT UUID_V1MC();   -- time-based, random multicast address instead of the MAC

-- Name-based: the same namespace and name always produce the same UUID
SELECT UUID_V5(UUID_NS_DNS(), 'example.com');
-- cfbff0d1-9375-5685-968c-48ce8b15ae17
SELECT UUID_V3(UUID_NS_DNS(), 'example.com');
-- 9073926b-929f-31c2-abc9-fad77ae3e8eb
```

Prefer **v7** for new primary keys: it sorts by creation time, which keeps
index inserts local, without disclosing a hardware address the way v1 does.

### Namespace and boundary constants

`UUID_NS_*` return text so they can be passed directly to `UUID_V3` and
`UUID_V5`, whose namespace argument is a string:

| Function | Value |
|---|---|
| `UUID_NS_DNS()` | `6ba7b810-9dad-11d1-80b4-00c04fd430c8` |
| `UUID_NS_URL()` | `6ba7b811-9dad-11d1-80b4-00c04fd430c8` |
| `UUID_NS_OID()` | `6ba7b812-9dad-11d1-80b4-00c04fd430c8` |
| `UUID_NS_X500()` | `6ba7b814-9dad-11d1-80b4-00c04fd430c8` |
| `UUID_NIL()` | `00000000-0000-0000-0000-000000000000` |
| `UUID_MAX()` | `ffffffff-ffff-ffff-ffff-ffffffffffff` |

### Introspection

The introspection functions take a `uuid` value — a column, or the result of a
generation function — not a string.

```sql
SELECT UUID_VERSION(id) FROM users;        -- 1, 3, 4, 5, 6, or 7
SELECT UUID_TIMESTAMP(id) FROM users;      -- '2026-08-05 21:29:00', or NULL
SELECT UUID_EPOCH(id) FROM users;          -- 1786066140, or NULL
SELECT UUID_COMPARE(a.id, b.id) FROM users a, users b WHERE ...;  -- -1, 0, 1
```

Because these are deterministic, they may be used in generated columns and
CHECK constraints:

```sql
CREATE TABLE audit_log (
  id  UUID NOT NULL,
  ver INT AS (UUID_VERSION(id)) STORED,
  CHECK (UUID_VERSION(id) IN (4, 7))   -- only v4 or v7 accepted
);
```

### Validation

`UUID_IS_VALID` reports whether a string would be accepted by a `uuid` column,
without raising an error:

```sql
SELECT UUID_IS_VALID('550e8400-e29b-41d4-a716-446655440000');  -- 1
SELECT UUID_IS_VALID('nope');                                  -- 0

CREATE TABLE staging (
  raw VARCHAR(40),
  CHECK (UUID_IS_VALID(raw) = 1)
);
```

## Function Reference

Every function below returns NULL when a required argument is NULL, unless
noted otherwise.

### Generation

| Signature | Returns | NULL / error behavior |
|---|---|---|
| `UUID_V1()` | `uuid` | Never NULL. Errors if the system RNG fails. |
| `UUID_V1MC()` | `uuid` | Never NULL. Errors if the system RNG fails. |
| `UUID_V3(namespace, name)` | `uuid` | NULL if either argument is NULL. NULL with a warning if `namespace` is not a valid UUID string — the statement continues. Empty `name` is valid. |
| `UUID_V4()` | `uuid` | Never NULL. Errors if the system RNG fails. |
| `UUID_V5(namespace, name)` | `uuid` | NULL if either argument is NULL. NULL with a warning if `namespace` is not a valid UUID string — the statement continues. Empty `name` is valid. |
| `UUID_V6()` | `uuid` | Never NULL. Errors if the system RNG fails. |
| `UUID_V7()` | `uuid` | Never NULL. Errors if the system RNG fails. |

`namespace` accepts any of the three textual forms below. `name` is hashed as
raw bytes, so it is case- and encoding-sensitive. A bad `namespace` is treated
as bad input data rather than a fatal condition, so a `SELECT` over a mix of
good and bad values still returns its good rows; note that in strict mode
MySQL promotes such a warning to an error on `INSERT` and `UPDATE`.

### Constants

| Signature | Returns | NULL / error behavior |
|---|---|---|
| `UUID_NIL()` | `uuid` | Never NULL. |
| `UUID_MAX()` | `uuid` | Never NULL. |
| `UUID_NS_DNS()` | text | Never NULL. |
| `UUID_NS_URL()` | text | Never NULL. |
| `UUID_NS_OID()` | text | Never NULL. |
| `UUID_NS_X500()` | text | Never NULL. |

### Introspection, validation, comparison

| Signature | Returns | NULL / error behavior |
|---|---|---|
| `UUID_VERSION(uuid)` | INT | NULL for NULL input. Returns the raw version nibble, so a value with no recognized version returns that nibble rather than an error (`UUID_VERSION(UUID_MAX())` is 15). |
| `UUID_TIMESTAMP(uuid)` | text `'YYYY-MM-DD HH:MM:SS'`, UTC | NULL for NULL input, for v3/v4/v5 (which carry no time), and for a v1/v6 value whose timestamp predates 1970-01-01. Truncated to whole seconds. |
| `UUID_EPOCH(uuid)` | INT, Unix seconds | Same NULL cases as `UUID_TIMESTAMP`. |
| `UUID_IS_VALID(string)` | INT `1` or `0` | NULL for NULL input. Never raises for any other input. |
| `UUID_COMPARE(uuid, uuid)` | INT `-1`, `0`, `1` | NULL if either argument is NULL. Compares the 16 bytes lexicographically. |

## Working with the `uuid` type

**Storage.** 16 bytes, fixed. Every row pays 16 bytes whether or not the
column is populated.

**Input.** A `uuid` column accepts three textual forms, all case-insensitive,
and all storing identical bytes:

```sql
INSERT INTO t VALUES ('550e8400e29b41d4a716446655440000');        -- 32 chars
INSERT INTO t VALUES ('550e8400-e29b-41d4-a716-446655440000');    -- 36 chars
INSERT INTO t VALUES ('{550e8400-e29b-41d4-a716-446655440000}');  -- 38 chars
```

Anything else is rejected at insert time:

```
ERROR 1366 (HY000): Incorrect uuid value: 'not-a-uuid' for column 'u' at row 1
```

**Reading values back.** Select the column directly — it renders as the
canonical lowercase 36-character form. **Do not use `CAST`**: custom types are
not part of MySQL's CAST grammar, in either direction.

```sql
SELECT u FROM t;                 -- correct
SELECT CAST(u AS CHAR) FROM t;   -- ERROR 1221: Incorrect usage of cast_as_char and uuid
```

To feed a UUID into a function that needs a character string with a declared
collation — the JSON functions in particular — convert explicitly:

```sql
SELECT JSON_OBJECT('ts', CONVERT(UUID_TIMESTAMP(u) USING utf8mb4)) FROM t;
```

**Aggregates.** `COUNT`, `COUNT(DISTINCT)`, `MIN`, `MAX`, and `GROUP_CONCAT`
work. `SUM` and `AVG` are rejected with `ERROR 1221`, as summing a UUID has no
meaning.

**Defaults.** A `NOT NULL` `uuid` column with no explicit `DEFAULT` rejects an
`INSERT` that omits it (`ERROR 1364`). Declare the default you want:

```sql
CREATE TABLE t (u UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000');
```

`ALTER TABLE ... ADD COLUMN u UUID NOT NULL` backfills existing rows with the
all-zero UUID.

## Known Limitations

These are current VillageSQL Extension Framework constraints, not choices made
by this extension. Each notes what would remove the need for the workaround.

| Limitation | Workaround |
|---|---|
| **`CAST` does not work with `uuid`** in either direction (`ERROR 1221`). Custom types are not wired into MySQL's CAST grammar. | Select the column directly to get text; insert text into a `uuid` column to go the other way. Tracked as [villagesql-server#204](https://github.com/villagesql/villagesql-server/issues/204) — 👍 it if this affects you. |
| **Upgrades need a server restart.** `ALTER EXTENSION <name> VERSION '<v>' AT RESTART` is the only upgrade form — `AT RESTART` is mandatory, so a new build never takes effect while the server is running. Separately, `UNINSTALL EXTENSION` is refused (`ERROR 3219`) while any column uses the `uuid` type. | Use `ALTER EXTENSION` and schedule a restart; dependent columns are preserved, so nothing needs dropping. Removed by [villagesql-server#697](https://github.com/villagesql/villagesql-server/issues/697), live upgrade without a restart. |
| **STRING results need `CONVERT` for JSON.** `JSON_OBJECT('ts', UUID_TIMESTAMP(u))` yields `"base64:type15:..."`, though `CHARSET()` reports `utf8mb4`. | Wrap in `CONVERT(... USING utf8mb4)`. The client-display half of this was fixed upstream in #612; the JSON half is tracked as [villagesql-server#938](https://github.com/villagesql/villagesql-server/issues/938). Related: [#348](https://github.com/villagesql/villagesql-server/issues/348), charset support in the ABI. |
| **No DATETIME return type** for extension functions, so `UUID_TIMESTAMP` returns text and truncates to whole seconds, discarding the sub-second precision v1/v6/v7 actually carry. | `CAST(UUID_TIMESTAMP(u) AS DATETIME)` for a temporal value; `UUID_EPOCH` for a number. Tracked as [villagesql-server#939](https://github.com/villagesql/villagesql-server/issues/939). |
| **`SUM` and `AVG` are rejected** over a `uuid` column (`ERROR 1221`). | None needed — summing a UUID is meaningless. `COUNT`, `COUNT(DISTINCT)`, `MIN`, `MAX` and `GROUP_CONCAT` all work. Tracked as [villagesql-server#605](https://github.com/villagesql/villagesql-server/issues/605), opt-in numeric promotion. |
| **No custom index access methods.** Index registration is available only as a preview API, which this extension does not use. | `PRIMARY KEY` and `UNIQUE` on a `uuid` column work and use the type's comparison function. Tracked as [#264](https://github.com/villagesql/villagesql-server/issues/264) (index type registration) and [#623](https://github.com/villagesql/villagesql-server/issues/623) (preview capabilities path to stability). |
| **`intrinsic_default_str` does not supply an INSERT default** — only the `ADD COLUMN` backfill path consults it, so `uuid NOT NULL` without an explicit `DEFAULT` rejects an `INSERT` that omits the column (`ERROR 1364`). | Declare an explicit column `DEFAULT`. Tracked as [villagesql-server#940](https://github.com/villagesql/villagesql-server/issues/940). |
| **`UUID_V7()` is ordered only to the millisecond.** The bits after the 48-bit timestamp are random with no monotonic counter, so two v7 values created in the same millisecond have random relative order. | Use `UUID_V6()`, which is monotonic per connection, or add an explicit sequence column. This is a deliberate scope decision for this release, not an SDK gap. |

## Security Considerations

- **`UUID_V1()` discloses the host's MAC address** in the low 48 bits of every
  value it produces, and its timestamp reveals when the row was created.
  Anything exposed to untrusted clients should use `UUID_V4()` (no embedded
  metadata) or `UUID_V1MC()` (random multicast address in place of the MAC).
  `UUID_V6()` and `UUID_V7()` also embed creation time.
- **v1, v6, and v7 values are partially predictable.** Their leading bits are a
  timestamp. Do not use them as session tokens, password-reset tokens, or
  anything else that must be unguessable — use `UUID_V4()`, which is 122 bits
  from the system CSPRNG.
- **v3 and v5 are not one-way.** They are unsalted MD5/SHA-1 of the namespace
  and name, so a UUID built from a low-entropy name (an email address, a
  sequential ID) can be brute-forced back to that name. Do not treat a v3 or
  v5 UUID as concealing its input. MD5 and SHA-1 are used here because RFC 9562
  specifies them, not for their collision resistance.
- **v4 and v7 depend on the system CSPRNG.** If OpenSSL's `RAND_bytes` fails,
  generation raises an error rather than returning a low-entropy value.

## Testing

See [TESTING.md](./TESTING.md) for prerequisites, build and install steps, how
to run the suite, how to regenerate expected output, and what each test file
covers.

```bash
cd "$VillageSQL_BUILD_DIR"/mysql-test
perl mysql-test-run.pl --suite=/absolute/path/to/vsql-uuid/mysql-test
```

## Development

### Project Structure

```
vsql-uuid/
├── src/
│   └── uuid.cc              # VDF implementations, UUID logic, extension registration
├── cmake/
│   └── FindVillageSQL.cmake # Locates the VillageSQL Extension SDK
├── mysql-test/
│   ├── t/                   # MTR test files
│   └── r/                   # MTR expected results (generated, never hand-edited)
├── build.sh                 # Configure and build
├── manifest.json            # VEB package manifest
├── CMakeLists.txt           # Build configuration
├── TESTING.md               # Test instructions
└── AGENTS.md                # Contributor and AI-assistant guidance
```

Conventions and the invariants every change must preserve are documented in
[AGENTS.md](./AGENTS.md).

## Contributing

VillageSQL welcomes contributions from the community. See the
[VillageSQL Contributing Guide](https://github.com/villagesql/villagesql-server/blob/main/CONTRIBUTING.md).

## Reporting Bugs and Requesting Features

Open an issue at
[github.com/villagesql/vsql-uuid/issues](https://github.com/villagesql/vsql-uuid/issues).
Please include:

- A clear and descriptive title
- A detailed description of the issue or feature request
- Steps to reproduce the bug, if applicable
- Your environment details (OS, VillageSQL version, extension version)

## Contact

We are excited you want to be part of the Village that makes VillageSQL happen.
You can interact with us and the community in several ways:

- File a [bug or issue](https://github.com/villagesql/vsql-uuid/issues) and we will review
- Start a [discussion](https://github.com/villagesql/vsql-uuid/discussions)
- Join the [Discord channel](https://discord.gg/KSr6whd3Fr)

## License

GPL-2.0. See the [LICENSE](./LICENSE) file.
