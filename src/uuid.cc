/* Copyright (c) 2025 VillageSQL Contributors
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <villagesql/vsql.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <string_view>

// For getting MAC address
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/types.h>
#ifdef __APPLE__
#include <net/if_dl.h>
#else
#include <linux/if_packet.h>
#include <net/if_arp.h>
#endif

// Use OpenSSL for MD5, SHA1, and secure random number generation
#include <openssl/evp.h>
#include <openssl/rand.h>

using vsql::CustomArg;
using vsql::CustomResult;
using vsql::IntResult;
using vsql::make_extension;
using vsql::make_func;
using vsql::make_type;
using vsql::StringArg;
using vsql::StringResult;
using vsql::INT;
using vsql::STRING;

static constexpr const char kUuidTypeName[] = "uuid";

// =============================================================================
// UUID Helper Functions
// =============================================================================

namespace uuid_funcs {

// UUID is stored as 16 bytes (128 bits) in binary format
static constexpr size_t kUuidBinarySize = 16;

// Length of the canonical UUID string representation:
// 32 hex characters (2 per byte) + 4 hyphens = 36 characters. This is an exact
// length, not an upper bound.
static constexpr size_t kUuidStringLength = 36;

// The three accepted textual input lengths.
static constexpr size_t kBareLength = kUuidBinarySize * 2;   // 32
static constexpr size_t kBracedLength = kUuidStringLength + 2;  // 38

// The node identifier occupies the last six bytes.
static constexpr size_t kNodeSize = 6;

// Predefined namespace UUIDs from RFC 9562
constexpr unsigned char kNamespaceDns[kUuidBinarySize] = {
    0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1,
    0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8};

constexpr unsigned char kNamespaceUrl[kUuidBinarySize] = {
    0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1,
    0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8};

constexpr unsigned char kNamespaceOid[kUuidBinarySize] = {
    0x6b, 0xa7, 0xb8, 0x12, 0x9d, 0xad, 0x11, 0xd1,
    0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8};

constexpr unsigned char kNamespaceX500[kUuidBinarySize] = {
    0x6b, 0xa7, 0xb8, 0x14, 0x9d, 0xad, 0x11, 0xd1,
    0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8};

// 100-nanosecond intervals between 1582-10-15 (the UUID v1/v6 epoch) and
// 1970-01-01 (the Unix epoch).
static constexpr uint64_t kUuidEpochOffset = 0x01B21DD213814000ULL;

// Byte 6 carries the version in its high nibble; byte 8 carries the RFC 9562
// variant in its top two bits.
static constexpr size_t kVersionByte = 6;
static constexpr size_t kVariantByte = 8;

// Which node identifier a time-based UUID should carry.
enum class NodeSource {
  kProcessNode,      // this host's address, stable for the process lifetime
  kRandomMulticast,  // fresh random multicast address, per call
};

static int hex_char_to_value(char c) noexcept {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// Offsets of the 16 byte-pairs within the hyphenated 36-character form.
static constexpr size_t kHyphenatedOffsets[kUuidBinarySize] = {
    0, 2, 4, 6, 9, 11, 14, 16, 19, 21, 24, 26, 28, 30, 32, 34};

// Positions of the four hyphens within the same form.
static constexpr size_t kHyphenPositions[4] = {8, 13, 18, 23};

// Parses the three accepted textual forms into 16 bytes:
//   32 chars  550e8400e29b41d4a716446655440000
//   36 chars  550e8400-e29b-41d4-a716-446655440000
//   38 chars  {550e8400-e29b-41d4-a716-446655440000}
// Validation and conversion share this single pass, so anything that parses
// here is exactly what a uuid column accepts.
bool parse_uuid_string(std::string_view text,
                       unsigned char *binary_uuid) noexcept {
  bool hyphenated;
  switch (text.size()) {
    case kBareLength:
      hyphenated = false;
      break;
    case kUuidStringLength:
      hyphenated = true;
      break;
    case kBracedLength:
      if (text.front() != '{' || text.back() != '}') return false;
      text = text.substr(1, kUuidStringLength);
      hyphenated = true;
      break;
    default:
      return false;
  }

  if (hyphenated) {
    for (size_t position : kHyphenPositions) {
      if (text[position] != '-') return false;
    }
  }

  for (size_t i = 0; i < kUuidBinarySize; ++i) {
    const size_t offset = hyphenated ? kHyphenatedOffsets[i] : i * 2;
    const int high = hex_char_to_value(text[offset]);
    const int low = hex_char_to_value(text[offset + 1]);
    if (high < 0 || low < 0) return false;
    binary_uuid[i] = static_cast<unsigned char>((high << 4) | low);
  }

  return true;
}

// Writes the canonical lowercase 36-character form. The caller guarantees at
// least kUuidStringLength bytes of capacity.
void format_uuid_string(const unsigned char *binary_uuid, char *out) noexcept {
  static constexpr char kHexChars[] = "0123456789abcdef";
  size_t pos = 0;
  for (size_t i = 0; i < kUuidBinarySize; ++i) {
    const unsigned char byte = binary_uuid[i];
    out[pos++] = kHexChars[byte >> 4];
    out[pos++] = kHexChars[byte & 0x0F];
    if (i == 3 || i == 5 || i == 7 || i == 9) out[pos++] = '-';
  }
}

// Stamps the RFC 9562 version nibble and variant bits in place. Always called
// after the timestamp fields are written, so it cannot be clobbered.
static void set_version_and_variant(unsigned char *binary_uuid,
                                    unsigned char version) noexcept {
  binary_uuid[kVersionByte] =
      (binary_uuid[kVersionByte] & 0x0F) | (version << 4);
  binary_uuid[kVariantByte] = (binary_uuid[kVariantByte] & 0x3F) | 0x80;
}

static int uuid_version_of(const unsigned char *binary_uuid) noexcept {
  return (binary_uuid[kVersionByte] >> 4) & 0x0F;
}

static bool random_bytes(unsigned char *out, size_t len) noexcept {
  return RAND_bytes(out, static_cast<int>(len)) == 1;
}

// Reads a hardware address from the first non-loopback interface that has one.
static bool get_real_mac_address(unsigned char node[kNodeSize]) noexcept {
  struct ifaddrs *ifap = nullptr;

  if (getifaddrs(&ifap) != 0) {
    return false;
  }

  static constexpr unsigned char kZeroAddress[kNodeSize] = {};
  bool found = false;

  for (struct ifaddrs *ifa = ifap; ifa != nullptr; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == nullptr) continue;
    if (ifa->ifa_flags & IFF_LOOPBACK) continue;

#ifdef __APPLE__
    // On macOS/BSD, hardware addresses are in the AF_LINK family
    if (ifa->ifa_addr->sa_family != AF_LINK) continue;
    struct sockaddr_dl *sdl =
        reinterpret_cast<struct sockaddr_dl *>(ifa->ifa_addr);
    if (sdl->sdl_alen != kNodeSize) continue;
    const unsigned char *mac = reinterpret_cast<unsigned char *>(LLADDR(sdl));
#else
    // On Linux, hardware addresses are in the AF_PACKET family
    if (ifa->ifa_addr->sa_family != AF_PACKET) continue;
    struct sockaddr_ll *sll =
        reinterpret_cast<struct sockaddr_ll *>(ifa->ifa_addr);
    if (sll->sll_hatype != ARPHRD_ETHER || sll->sll_halen != kNodeSize) continue;
    const unsigned char *mac = sll->sll_addr;
#endif

    // Skip unconfigured interfaces
    if (memcmp(mac, kZeroAddress, kNodeSize) == 0) continue;

    memcpy(node, mac, kNodeSize);
    found = true;
    break;
  }

  freeifaddrs(ifap);
  return found;
}

struct NodeId {
  bool ok;
  std::array<unsigned char, kNodeSize> bytes;
};

// The node identifier is fixed for the life of the process, so the interface
// scan runs once instead of once per generated UUID. Initialization of a
// function-local static is thread-safe and the value is never mutated
// afterwards, which keeps the generators re-entrant.
static const NodeId &process_node_id() noexcept {
  static const NodeId node = [] {
    NodeId n{true, {}};
    if (get_real_mac_address(n.bytes.data())) return n;
    // No usable hardware address. RFC 9562 section 6.10 requires a
    // random node to set the multicast bit, so it can never be mistaken
    // for a real IEEE 802 address.
    if (!random_bytes(n.bytes.data(), n.bytes.size())) return NodeId{false, {}};
    n.bytes[0] |= 0x01;
    return n;
  }();
  return node;
}

// A random multicast node, regenerated per call so v1mc never discloses a
// hardware address.
static bool multicast_node_id(unsigned char node[kNodeSize]) noexcept {
  if (!random_bytes(node, kNodeSize)) return false;
  node[0] |= 0x01;  // Multicast bit
  return true;
}

// Handed out once per thread, never per row. Combining a random base with this
// counter makes every thread's clock sequence both unpredictable and distinct
// from every other thread's (for up to 16384 threads), which is what keeps two
// threads from emitting the same v1/v6 UUID inside one clock tick. An atomic
// increment is the narrowest possible synchronization for that guarantee.
static std::atomic<uint16_t> g_clock_seq_counter{0};

struct ClockSeq {
  bool ok;
  uint16_t value;
};

static const ClockSeq &thread_clock_seq() noexcept {
  static thread_local const ClockSeq seq = [] {
    unsigned char bytes[2];
    if (!random_bytes(bytes, sizeof(bytes))) return ClockSeq{false, 0};
    const uint16_t base = static_cast<uint16_t>((bytes[0] << 8) | bytes[1]);
    const uint16_t offset =
        g_clock_seq_counter.fetch_add(1, std::memory_order_relaxed);
    return ClockSeq{true, static_cast<uint16_t>((base + offset) & 0x3FFF)};
  }();
  return seq;
}

// Current time in the units RFC 9562 uses for v1 and v6: 100-nanosecond
// intervals since 1582-10-15. The system clock is read at microsecond
// resolution, so the low decimal digit is always zero — see
// next_uuid_timestamp for why that does not cause collisions.
static uint64_t current_uuid_timestamp() noexcept {
  const auto now = std::chrono::system_clock::now().time_since_epoch();
  const auto microseconds =
      std::chrono::duration_cast<std::chrono::microseconds>(now);
  return (static_cast<uint64_t>(microseconds.count()) * 10) + kUuidEpochOffset;
}

// Consecutive calls within one microsecond would otherwise share a timestamp
// and — with a fixed node and clock sequence — produce identical v1/v6 UUIDs.
// Advancing past the last value handed out keeps them unique and monotonic
// within a thread. After a backwards clock step this runs ahead of the real
// clock until the clock catches up; uniqueness is the property worth keeping.
static uint64_t next_uuid_timestamp() noexcept {
  static thread_local uint64_t last = 0;
  uint64_t timestamp = current_uuid_timestamp();
  if (timestamp <= last) timestamp = last + 1;
  last = timestamp;
  return timestamp;
}

// Writes the clock sequence and node fields shared by v1 and v6 (bytes 8-15).
static bool fill_clock_seq_and_node(unsigned char *binary_uuid,
                                    NodeSource source) noexcept {
  const ClockSeq &clock_seq = thread_clock_seq();
  if (!clock_seq.ok) return false;

  binary_uuid[8] = (clock_seq.value >> 8) & 0x3F;
  binary_uuid[9] = clock_seq.value & 0xFF;

  if (source == NodeSource::kRandomMulticast) {
    return multicast_node_id(&binary_uuid[10]);
  }

  const NodeId &node = process_node_id();
  if (!node.ok) return false;
  memcpy(&binary_uuid[10], node.bytes.data(), kNodeSize);
  return true;
}

bool generate_uuid_v1(unsigned char *binary_uuid, NodeSource source) noexcept {
  const uint64_t timestamp = next_uuid_timestamp();

  // Only the low 60 bits of the timestamp are representable; the layout runs
  // out in the year 5236.
  // time_low  = timestamp[31:0]  -> bytes 0-3
  binary_uuid[0] = (timestamp >> 24) & 0xFF;
  binary_uuid[1] = (timestamp >> 16) & 0xFF;
  binary_uuid[2] = (timestamp >> 8) & 0xFF;
  binary_uuid[3] = timestamp & 0xFF;

  // time_mid  = timestamp[47:32] -> bytes 4-5
  binary_uuid[4] = (timestamp >> 40) & 0xFF;
  binary_uuid[5] = (timestamp >> 32) & 0xFF;

  // time_high = timestamp[59:48] -> byte 6 low nibble, byte 7
  binary_uuid[6] = (timestamp >> 56) & 0x0F;
  binary_uuid[7] = (timestamp >> 48) & 0xFF;

  if (!fill_clock_seq_and_node(binary_uuid, source)) return false;

  set_version_and_variant(binary_uuid, 1);
  return true;
}

bool generate_uuid_v6(unsigned char *binary_uuid, NodeSource source) noexcept {
  const uint64_t timestamp = next_uuid_timestamp();

  // v6 stores the same 60-bit timestamp most-significant bits first, so byte
  // order matches chronological order.
  // timestamp[59:28] -> bytes 0-3
  binary_uuid[0] = (timestamp >> 52) & 0xFF;
  binary_uuid[1] = (timestamp >> 44) & 0xFF;
  binary_uuid[2] = (timestamp >> 36) & 0xFF;
  binary_uuid[3] = (timestamp >> 28) & 0xFF;

  // timestamp[27:12] -> bytes 4-5
  binary_uuid[4] = (timestamp >> 20) & 0xFF;
  binary_uuid[5] = (timestamp >> 12) & 0xFF;

  // timestamp[11:0]  -> byte 6 low nibble, byte 7
  binary_uuid[6] = (timestamp >> 8) & 0x0F;
  binary_uuid[7] = timestamp & 0xFF;

  if (!fill_clock_seq_and_node(binary_uuid, source)) return false;

  set_version_and_variant(binary_uuid, 6);
  return true;
}

bool generate_uuid_v4(unsigned char *binary_uuid) noexcept {
  // 128 bits of cryptographically secure random data, then overwrite the
  // version and variant fields.
  if (!random_bytes(binary_uuid, kUuidBinarySize)) return false;
  set_version_and_variant(binary_uuid, 4);
  return true;
}

bool generate_uuid_v7(unsigned char *binary_uuid) noexcept {
  const auto now = std::chrono::system_clock::now().time_since_epoch();
  const uint64_t unix_ts_ms = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(now).count());

  if (!random_bytes(binary_uuid, kUuidBinarySize)) return false;

  // Unix timestamp in milliseconds, 48 bits big-endian -> bytes 0-5. The
  // remaining bits stay random: ordering is therefore only guaranteed between
  // values created in different milliseconds.
  binary_uuid[0] = (unix_ts_ms >> 40) & 0xFF;
  binary_uuid[1] = (unix_ts_ms >> 32) & 0xFF;
  binary_uuid[2] = (unix_ts_ms >> 24) & 0xFF;
  binary_uuid[3] = (unix_ts_ms >> 16) & 0xFF;
  binary_uuid[4] = (unix_ts_ms >> 8) & 0xFF;
  binary_uuid[5] = unix_ts_ms & 0xFF;

  set_version_and_variant(binary_uuid, 7);
  return true;
}

// v3 and v5 differ only in the digest algorithm, which the version selects:
// v3 is MD5 and v5 is SHA-1. Both hash the namespace followed by the name and
// keep the leading 16 bytes of the digest.
bool generate_uuid_named(unsigned char version,
                         const unsigned char *namespace_uuid,
                         std::string_view name,
                         unsigned char *binary_uuid) noexcept {
  const EVP_MD *algorithm = (version == 3) ? EVP_md5() : EVP_sha1();

  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int digest_len = 0;

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (ctx == nullptr) return false;

  const bool ok = EVP_DigestInit_ex(ctx, algorithm, nullptr) == 1 &&
                  EVP_DigestUpdate(ctx, namespace_uuid, kUuidBinarySize) == 1 &&
                  EVP_DigestUpdate(ctx, name.data(), name.size()) == 1 &&
                  EVP_DigestFinal_ex(ctx, digest, &digest_len) == 1;
  EVP_MD_CTX_free(ctx);

  if (!ok || digest_len < kUuidBinarySize) return false;

  memcpy(binary_uuid, digest, kUuidBinarySize);
  set_version_and_variant(binary_uuid, version);
  return true;
}

// Recovers whole Unix seconds from the timestamp embedded in a v1, v6, or v7
// UUID. Returns false for every other version, and for v1/v6 values that
// predate the Unix epoch. Each case is the exact inverse of the corresponding
// generator's field layout above.
bool extract_unix_seconds(const unsigned char *binary_uuid,
                          int64_t *unix_seconds) noexcept {
  uint64_t intervals = 0;

  switch (uuid_version_of(binary_uuid)) {
    case 1:
      intervals = (static_cast<uint64_t>(binary_uuid[6] & 0x0F) << 56) |
                  (static_cast<uint64_t>(binary_uuid[7]) << 48) |
                  (static_cast<uint64_t>(binary_uuid[4]) << 40) |
                  (static_cast<uint64_t>(binary_uuid[5]) << 32) |
                  (static_cast<uint64_t>(binary_uuid[0]) << 24) |
                  (static_cast<uint64_t>(binary_uuid[1]) << 16) |
                  (static_cast<uint64_t>(binary_uuid[2]) << 8) |
                  static_cast<uint64_t>(binary_uuid[3]);
      break;
    case 6:
      intervals = (static_cast<uint64_t>(binary_uuid[0]) << 52) |
                  (static_cast<uint64_t>(binary_uuid[1]) << 44) |
                  (static_cast<uint64_t>(binary_uuid[2]) << 36) |
                  (static_cast<uint64_t>(binary_uuid[3]) << 28) |
                  (static_cast<uint64_t>(binary_uuid[4]) << 20) |
                  (static_cast<uint64_t>(binary_uuid[5]) << 12) |
                  (static_cast<uint64_t>(binary_uuid[6] & 0x0F) << 8) |
                  static_cast<uint64_t>(binary_uuid[7]);
      break;
    case 7: {
      const uint64_t unix_ts_ms =
          (static_cast<uint64_t>(binary_uuid[0]) << 40) |
          (static_cast<uint64_t>(binary_uuid[1]) << 32) |
          (static_cast<uint64_t>(binary_uuid[2]) << 24) |
          (static_cast<uint64_t>(binary_uuid[3]) << 16) |
          (static_cast<uint64_t>(binary_uuid[4]) << 8) |
          static_cast<uint64_t>(binary_uuid[5]);
      *unix_seconds = static_cast<int64_t>(unix_ts_ms / 1000);
      return true;
    }
    default:
      return false;
  }

  if (intervals < kUuidEpochOffset) return false;
  *unix_seconds =
      static_cast<int64_t>((intervals - kUuidEpochOffset) / 10000000ULL);
  return true;
}

}  // namespace uuid_funcs

using uuid_funcs::extract_unix_seconds;
using uuid_funcs::format_uuid_string;
using uuid_funcs::generate_uuid_named;
using uuid_funcs::generate_uuid_v1;
using uuid_funcs::generate_uuid_v4;
using uuid_funcs::generate_uuid_v6;
using uuid_funcs::generate_uuid_v7;
using uuid_funcs::kNamespaceDns;
using uuid_funcs::kNamespaceOid;
using uuid_funcs::kNamespaceUrl;
using uuid_funcs::kNamespaceX500;
using uuid_funcs::kUuidBinarySize;
using uuid_funcs::kUuidStringLength;
using uuid_funcs::NodeSource;
using uuid_funcs::parse_uuid_string;
using uuid_funcs::uuid_version_of;

// =============================================================================
// UUID Type Functions (encode, decode, compare)
// =============================================================================

// Encode (from_string): string -> 16-byte binary
void uuid_encode(std::string_view from, CustomResult out) try {
  auto buf = out.buffer();
  if (buf.size() < kUuidBinarySize) {
    out.error("uuid encode: buffer too small");
    return;
  }
  if (!parse_uuid_string(from, buf.data())) {
    out.error("invalid UUID format");
    return;
  }
  out.set_length(kUuidBinarySize);
} catch (...) {
  out.error("uuid encode: unexpected internal error");
}

// Decode (to_string): 16-byte binary -> 36-char string
void uuid_decode(CustomArg in, StringResult out) try {
  auto span = in.value();
  if (span.size() < kUuidBinarySize) {
    out.error("uuid decode: unexpected buffer size");
    return;
  }
  auto buf = out.buffer();
  if (buf.size() < kUuidStringLength) {
    out.error("uuid decode: output buffer too small");
    return;
  }
  format_uuid_string(span.data(), buf.data());
  out.set_length(kUuidStringLength);
} catch (...) {
  out.error("uuid decode: unexpected internal error");
}

// Compare: lexicographic comparison of binary UUIDs. This is the ordering the
// server uses for sorting and indexing, and UUID_COMPARE delegates to it so
// the two can never disagree. memcmp cannot throw, so no handler is needed —
// and an int return has no way to report one.
int uuid_compare(CustomArg a, CustomArg b) {
  auto sa = a.value(), sb = b.value();
  // Both inputs are kUuidBinarySize bytes (guaranteed by persisted_length).
  if (sa.size() < kUuidBinarySize || sb.size() < kUuidBinarySize) {
    return (sa.size() < sb.size()) ? -1 : (sa.size() > sb.size()) ? 1 : 0;
  }
  return memcmp(sa.data(), sb.data(), kUuidBinarySize);
}

// =============================================================================
// VDF Implementations
// =============================================================================

// Publishes a generated UUID as the function result, reporting rather than
// overrunning a buffer the server sized too small. Every UUID-returning
// function declares buffer_size(kUuidBinarySize), so the short-buffer arm is a
// guard against a registration mistake, not an expected path.
static void set_uuid_result(const unsigned char *binary_uuid,
                            CustomResult &out, const char *error_message) {
  auto buf = out.buffer();
  if (buf.size() < kUuidBinarySize) {
    out.error(error_message);
    return;
  }
  memcpy(buf.data(), binary_uuid, kUuidBinarySize);
  out.set_length(kUuidBinarySize);
}

// Emits one of the fixed RFC 9562 namespace UUIDs in canonical text form, so
// it can be passed straight to UUID_V3 / UUID_V5.
static void set_namespace_result(const unsigned char *namespace_uuid,
                                 StringResult &out,
                                 const char *error_message) {
  auto buf = out.buffer();
  if (buf.size() < kUuidStringLength) {
    out.error(error_message);
    return;
  }
  format_uuid_string(namespace_uuid, buf.data());
  out.set_length(kUuidStringLength);
}

// Reads the 16 bytes behind a uuid argument. Returns false when the caller
// should return immediately: either the argument was NULL or its size was
// wrong, and in both cases the result has already been set.
template <typename Result>
static bool uuid_bytes_of(CustomArg arg, Result &out,
                          const unsigned char **bytes) {
  if (arg.is_null()) {
    out.set_null();
    return false;
  }
  auto span = arg.value();
  if (span.size() < kUuidBinarySize) {
    out.error("uuid: unexpected value size");
    return false;
  }
  *bytes = span.data();
  return true;
}

void uuid_generate_v1_impl(CustomResult out) try {
  unsigned char binary_uuid[kUuidBinarySize];
  if (!generate_uuid_v1(binary_uuid, NodeSource::kProcessNode)) {
    out.error("UUID_V1: failed to generate a UUID");
    return;
  }
  set_uuid_result(binary_uuid, out, "UUID_V1: result buffer too small");
} catch (...) {
  out.error("UUID_V1: unexpected internal error");
}

void uuid_generate_v1mc_impl(CustomResult out) try {
  unsigned char binary_uuid[kUuidBinarySize];
  if (!generate_uuid_v1(binary_uuid, NodeSource::kRandomMulticast)) {
    out.error("UUID_V1MC: failed to generate a UUID");
    return;
  }
  set_uuid_result(binary_uuid, out, "UUID_V1MC: result buffer too small");
} catch (...) {
  out.error("UUID_V1MC: unexpected internal error");
}

void uuid_generate_v3_impl(StringArg ns_arg, StringArg name_arg,
                           CustomResult out) try {
  if (ns_arg.is_null() || name_arg.is_null()) {
    out.set_null();
    return;
  }
  unsigned char namespace_binary[kUuidBinarySize];
  if (!parse_uuid_string(ns_arg.value(), namespace_binary)) {
    out.error("UUID_V3: invalid namespace UUID format");
    return;
  }
  unsigned char binary_uuid[kUuidBinarySize];
  if (!generate_uuid_named(3, namespace_binary, name_arg.value(),
                           binary_uuid)) {
    out.error("UUID_V3: failed to generate a UUID");
    return;
  }
  set_uuid_result(binary_uuid, out, "UUID_V3: result buffer too small");
} catch (...) {
  out.error("UUID_V3: unexpected internal error");
}

void uuid_generate_v4_impl(CustomResult out) try {
  unsigned char binary_uuid[kUuidBinarySize];
  if (!generate_uuid_v4(binary_uuid)) {
    out.error("UUID_V4: failed to generate a UUID");
    return;
  }
  set_uuid_result(binary_uuid, out, "UUID_V4: result buffer too small");
} catch (...) {
  out.error("UUID_V4: unexpected internal error");
}

void uuid_generate_v5_impl(StringArg ns_arg, StringArg name_arg,
                           CustomResult out) try {
  if (ns_arg.is_null() || name_arg.is_null()) {
    out.set_null();
    return;
  }
  unsigned char namespace_binary[kUuidBinarySize];
  if (!parse_uuid_string(ns_arg.value(), namespace_binary)) {
    out.error("UUID_V5: invalid namespace UUID format");
    return;
  }
  unsigned char binary_uuid[kUuidBinarySize];
  if (!generate_uuid_named(5, namespace_binary, name_arg.value(),
                           binary_uuid)) {
    out.error("UUID_V5: failed to generate a UUID");
    return;
  }
  set_uuid_result(binary_uuid, out, "UUID_V5: result buffer too small");
} catch (...) {
  out.error("UUID_V5: unexpected internal error");
}

void uuid_generate_v6_impl(CustomResult out) try {
  unsigned char binary_uuid[kUuidBinarySize];
  if (!generate_uuid_v6(binary_uuid, NodeSource::kProcessNode)) {
    out.error("UUID_V6: failed to generate a UUID");
    return;
  }
  set_uuid_result(binary_uuid, out, "UUID_V6: result buffer too small");
} catch (...) {
  out.error("UUID_V6: unexpected internal error");
}

void uuid_generate_v7_impl(CustomResult out) try {
  unsigned char binary_uuid[kUuidBinarySize];
  if (!generate_uuid_v7(binary_uuid)) {
    out.error("UUID_V7: failed to generate a UUID");
    return;
  }
  set_uuid_result(binary_uuid, out, "UUID_V7: result buffer too small");
} catch (...) {
  out.error("UUID_V7: unexpected internal error");
}

void uuid_nil_impl(CustomResult out) try {
  // RFC 9562 section 5.9: all 128 bits zero.
  std::array<unsigned char, kUuidBinarySize> binary_uuid{};
  set_uuid_result(binary_uuid.data(), out, "UUID_NIL: result buffer too small");
} catch (...) {
  out.error("UUID_NIL: unexpected internal error");
}

void uuid_max_impl(CustomResult out) try {
  // RFC 9562 section 5.10: all 128 bits set.
  std::array<unsigned char, kUuidBinarySize> binary_uuid{};
  binary_uuid.fill(0xFF);
  set_uuid_result(binary_uuid.data(), out, "UUID_MAX: result buffer too small");
} catch (...) {
  out.error("UUID_MAX: unexpected internal error");
}

void uuid_ns_dns_impl(StringResult out) try {
  set_namespace_result(kNamespaceDns, out,
                       "UUID_NS_DNS: result buffer too small");
} catch (...) {
  out.error("UUID_NS_DNS: unexpected internal error");
}

void uuid_ns_url_impl(StringResult out) try {
  set_namespace_result(kNamespaceUrl, out,
                       "UUID_NS_URL: result buffer too small");
} catch (...) {
  out.error("UUID_NS_URL: unexpected internal error");
}

void uuid_ns_oid_impl(StringResult out) try {
  set_namespace_result(kNamespaceOid, out,
                       "UUID_NS_OID: result buffer too small");
} catch (...) {
  out.error("UUID_NS_OID: unexpected internal error");
}

void uuid_ns_x500_impl(StringResult out) try {
  set_namespace_result(kNamespaceX500, out,
                       "UUID_NS_X500: result buffer too small");
} catch (...) {
  out.error("UUID_NS_X500: unexpected internal error");
}

// Reports whether a string would be accepted by a uuid column, without
// raising an error when it would not.
void uuid_is_valid_impl(StringArg arg, IntResult out) try {
  if (arg.is_null()) {
    out.set_null();
    return;
  }
  unsigned char binary_uuid[kUuidBinarySize];
  out.set(parse_uuid_string(arg.value(), binary_uuid) ? 1 : 0);
} catch (...) {
  out.error("UUID_IS_VALID: unexpected internal error");
}

void uuid_version_impl(CustomArg arg, IntResult out) try {
  const unsigned char *bytes = nullptr;
  if (!uuid_bytes_of(arg, out, &bytes)) return;
  out.set(uuid_version_of(bytes));
} catch (...) {
  out.error("UUID_VERSION: unexpected internal error");
}

void uuid_timestamp_impl(CustomArg arg, StringResult out) try {
  const unsigned char *bytes = nullptr;
  if (!uuid_bytes_of(arg, out, &bytes)) return;

  int64_t unix_seconds = 0;
  if (!extract_unix_seconds(bytes, &unix_seconds)) {
    out.set_null();
    return;
  }

  const time_t seconds = static_cast<time_t>(unix_seconds);
  struct tm tm_buf;
  if (gmtime_r(&seconds, &tm_buf) == nullptr) {
    out.set_null();
    return;
  }
  char buf[20];
  const size_t len = strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_buf);
  if (len == 0) {
    out.set_null();
    return;
  }
  out.set(std::string_view(buf, len));
} catch (...) {
  out.error("UUID_TIMESTAMP: unexpected internal error");
}

void uuid_epoch_impl(CustomArg arg, IntResult out) try {
  const unsigned char *bytes = nullptr;
  if (!uuid_bytes_of(arg, out, &bytes)) return;

  int64_t unix_seconds = 0;
  if (!extract_unix_seconds(bytes, &unix_seconds)) {
    out.set_null();
    return;
  }
  out.set(unix_seconds);
} catch (...) {
  out.error("UUID_EPOCH: unexpected internal error");
}

void uuid_compare_impl(CustomArg a, CustomArg b, IntResult out) try {
  if (a.is_null() || b.is_null()) {
    out.set_null();
    return;
  }
  if (a.value().size() < kUuidBinarySize || b.value().size() < kUuidBinarySize) {
    out.error("UUID_COMPARE: unexpected value size");
    return;
  }
  const int cmp = uuid_compare(a, b);
  out.set((cmp < 0) ? -1 : (cmp > 0) ? 1 : 0);
} catch (...) {
  out.error("UUID_COMPARE: unexpected internal error");
}

// =============================================================================
// Extension Registration
// =============================================================================

constexpr auto UUID =
    make_type<kUuidTypeName>()
        .persisted_length(kUuidBinarySize)
        .max_decode_buffer_length(kUuidStringLength + 1)
        .from_string<&uuid_encode>()
        .to_string<&uuid_decode>()
        .compare<&uuid_compare>()
        .intrinsic_default_str("00000000-0000-0000-0000-000000000000")
        .build();

VEF_GENERATE_ENTRY_POINTS(
    make_extension()
        .type(UUID)

        .func(make_func<&uuid_generate_v1_impl>("UUID_V1")
                  .returns(UUID)
                  .no_params()
                  .buffer_size(kUuidBinarySize)
                  .build())

        .func(make_func<&uuid_generate_v1mc_impl>("UUID_V1MC")
                  .returns(UUID)
                  .no_params()
                  .buffer_size(kUuidBinarySize)
                  .build())

        .func(make_func<&uuid_generate_v3_impl>("UUID_V3")
                  .returns(UUID)
                  .param(STRING)
                  .param(STRING)
                  .buffer_size(kUuidBinarySize)
                  .deterministic(true)
                  .build())

        .func(make_func<&uuid_generate_v4_impl>("UUID_V4")
                  .returns(UUID)
                  .no_params()
                  .buffer_size(kUuidBinarySize)
                  .build())

        .func(make_func<&uuid_generate_v5_impl>("UUID_V5")
                  .returns(UUID)
                  .param(STRING)
                  .param(STRING)
                  .buffer_size(kUuidBinarySize)
                  .deterministic(true)
                  .build())

        .func(make_func<&uuid_generate_v6_impl>("UUID_V6")
                  .returns(UUID)
                  .no_params()
                  .buffer_size(kUuidBinarySize)
                  .build())

        .func(make_func<&uuid_generate_v7_impl>("UUID_V7")
                  .returns(UUID)
                  .no_params()
                  .buffer_size(kUuidBinarySize)
                  .build())

        .func(make_func<&uuid_nil_impl>("UUID_NIL")
                  .returns(UUID)
                  .no_params()
                  .buffer_size(kUuidBinarySize)
                  .deterministic(true)
                  .build())

        .func(make_func<&uuid_max_impl>("UUID_MAX")
                  .returns(UUID)
                  .no_params()
                  .buffer_size(kUuidBinarySize)
                  .deterministic(true)
                  .build())

        .func(make_func<&uuid_ns_dns_impl>("UUID_NS_DNS")
                  .returns(STRING)
                  .no_params()
                  .buffer_size(kUuidStringLength + 1)
                  .deterministic(true)
                  .build())

        .func(make_func<&uuid_ns_url_impl>("UUID_NS_URL")
                  .returns(STRING)
                  .no_params()
                  .buffer_size(kUuidStringLength + 1)
                  .deterministic(true)
                  .build())

        .func(make_func<&uuid_ns_oid_impl>("UUID_NS_OID")
                  .returns(STRING)
                  .no_params()
                  .buffer_size(kUuidStringLength + 1)
                  .deterministic(true)
                  .build())

        .func(make_func<&uuid_ns_x500_impl>("UUID_NS_X500")
                  .returns(STRING)
                  .no_params()
                  .buffer_size(kUuidStringLength + 1)
                  .deterministic(true)
                  .build())

        .func(make_func<&uuid_is_valid_impl>("UUID_IS_VALID")
                  .returns(INT)
                  .param(STRING)
                  .deterministic(true)
                  .build())

        .func(make_func<&uuid_compare_impl>("UUID_COMPARE")
                  .returns(INT)
                  .param(UUID)
                  .param(UUID)
                  .deterministic(true)
                  .build())

        .func(make_func<&uuid_version_impl>("UUID_VERSION")
                  .returns(INT)
                  .param(UUID)
                  .deterministic(true)
                  .build())

        .func(make_func<&uuid_timestamp_impl>("UUID_TIMESTAMP")
                  .returns(STRING)
                  .param(UUID)
                  .buffer_size(20)
                  .deterministic(true)
                  .build())

        .func(make_func<&uuid_epoch_impl>("UUID_EPOCH")
                  .returns(INT)
                  .param(UUID)
                  .deterministic(true)
                  .build()))
