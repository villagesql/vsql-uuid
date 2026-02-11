// Copyright (c) 2025 VillageSQL Inc. and Contributors

#include <villagesql/extension.h>

#include <cctype>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <random>
#include <string>

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

using namespace villagesql::extension_builder;
using namespace villagesql::func_builder;
using namespace villagesql::type_builder;

// Custom type name constant
constexpr const char* UUID = "uuid";

// =============================================================================
// UUID Helper Functions
// =============================================================================

namespace uuid_funcs {

// UUID is stored as 16 bytes (128 bits) in binary format
static constexpr size_t kUuidBinarySize = 16;

// Maximum length for UUID string representation (36 chars for standard format)
// 32 hex characters (2 per byte) + 4 hyphens = 36 total characters
static constexpr size_t kUuidStringMaxLength = 36;

// Predefined namespace UUIDs from RFC 9562
const unsigned char kNamespaceDns[16] = {0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad,
                                         0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0,
                                         0x4f, 0xd4, 0x30, 0xc8};

const unsigned char kNamespaceUrl[16] = {0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad,
                                         0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0,
                                         0x4f, 0xd4, 0x30, 0xc8};

const unsigned char kNamespaceOid[16] = {0x6b, 0xa7, 0xb8, 0x12, 0x9d, 0xad,
                                         0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0,
                                         0x4f, 0xd4, 0x30, 0xc8};

const unsigned char kNamespaceX500[16] = {0x6b, 0xa7, 0xb8, 0x14, 0x9d, 0xad,
                                          0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0,
                                          0x4f, 0xd4, 0x30, 0xc8};

bool is_hex_digit(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
         (c >= 'A' && c <= 'F');
}

int hex_char_to_value(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

bool validate_uuid_format(const char* uuid_str, size_t str_len) {
  if (!uuid_str) return false;

  // Handle different valid lengths
  bool has_braces = false;
  bool has_hyphens = false;

  if (str_len == 32) {
    // Format: 550e8400e29b41d4a716446655440000 (no hyphens, no braces)
    has_hyphens = false;
  } else if (str_len == 36) {
    // Format: 550e8400-e29b-41d4-a716-446655440000 (with hyphens)
    has_hyphens = true;
  } else if (str_len == 38) {
    // Format: {550e8400-e29b-41d4-a716-446655440000} (with braces and hyphens)
    if (uuid_str[0] != '{' || uuid_str[37] != '}') return false;
    has_braces = true;
    has_hyphens = true;
  } else {
    return false;
  }

  const char* start = has_braces ? uuid_str + 1 : uuid_str;

  if (has_hyphens) {
    // Check hyphen positions: 8-4-4-4-12
    if (start[8] != '-' || start[13] != '-' || start[18] != '-' ||
        start[23] != '-') {
      return false;
    }

    // Check hex digits in each segment
    for (size_t i = 0; i < 36; ++i) {
      if (i == 8 || i == 13 || i == 18 || i == 23) {
        continue;  // Skip hyphens
      }
      if (!is_hex_digit(start[i])) return false;
    }
  } else {
    // No hyphens - just check all 32 characters are hex
    for (size_t i = 0; i < 32; ++i) {
      if (!is_hex_digit(start[i])) return false;
    }
  }

  return true;
}

bool parse_uuid_string(const char* uuid_str, size_t str_len,
                       unsigned char* binary_uuid) {
  if (!uuid_str || !binary_uuid) return false;

  if (!validate_uuid_format(uuid_str, str_len)) return false;

  // Determine format and get to the actual hex digits
  const char* hex_start = uuid_str;
  bool has_hyphens = false;

  if (str_len == 38) {
    // Has braces: {550e8400-e29b-41d4-a716-446655440000}
    hex_start = uuid_str + 1;
    has_hyphens = true;
  } else if (str_len == 36) {
    // Has hyphens: 550e8400-e29b-41d4-a716-446655440000
    has_hyphens = true;
  } else if (str_len != 32) {
    // Invalid length - must be 32, 36, or 38 characters
    return false;
  }
  // else str_len == 32, no hyphens: 550e8400e29b41d4a716446655440000

  // Parse hex digits into binary
  size_t binary_idx = 0;
  size_t hex_idx = 0;

  while (binary_idx < kUuidBinarySize && hex_idx < (has_hyphens ? 36 : 32)) {
    // Skip hyphens
    if (has_hyphens &&
        (hex_idx == 8 || hex_idx == 13 || hex_idx == 18 || hex_idx == 23)) {
      hex_idx++;
      continue;
    }

    // Parse two hex digits into one byte
    int high_nibble = hex_char_to_value(hex_start[hex_idx]);
    int low_nibble = hex_char_to_value(hex_start[hex_idx + 1]);

    if (high_nibble < 0 || low_nibble < 0) return false;

    binary_uuid[binary_idx] =
        static_cast<unsigned char>((high_nibble << 4) | low_nibble);
    binary_idx++;
    hex_idx += 2;
  }

  return binary_idx == kUuidBinarySize;
}

bool format_uuid_binary(const unsigned char* binary_uuid,
                        std::string* uuid_str) {
  if (!binary_uuid || !uuid_str) return false;

  static const char hex_chars[] = "0123456789abcdef";

  uuid_str->reserve(kUuidStringMaxLength);
  uuid_str->clear();

  // Format as: 550e8400-e29b-41d4-a716-446655440000
  for (size_t i = 0; i < kUuidBinarySize; ++i) {
    unsigned char byte = binary_uuid[i];
    uuid_str->push_back(hex_chars[byte >> 4]);
    uuid_str->push_back(hex_chars[byte & 0x0F]);

    // Add hyphens at positions 4, 6, 8, 10 (after bytes 3, 5, 7, 9)
    if (i == 3 || i == 5 || i == 7 || i == 9) {
      uuid_str->push_back('-');
    }
  }

  return true;
}

// Helper function to get a real MAC address from network interfaces
static bool get_real_mac_address(unsigned char node[6]) {
  struct ifaddrs* ifap = nullptr;

  if (getifaddrs(&ifap) != 0) {
    return false;
  }

  bool found = false;
  for (struct ifaddrs* ifa = ifap; ifa != nullptr; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == nullptr) continue;

#ifdef __APPLE__
    // On macOS/BSD, hardware addresses are in AF_LINK family
    if (ifa->ifa_addr->sa_family == AF_LINK) {
      struct sockaddr_dl* sdl =
          reinterpret_cast<struct sockaddr_dl*>(ifa->ifa_addr);

      // Skip if no hardware address or wrong length
      if (sdl->sdl_alen != 6) continue;

      // Skip loopback interfaces
      if (ifa->ifa_flags & IFF_LOOPBACK) continue;

      // Get the MAC address
      unsigned char* mac = reinterpret_cast<unsigned char*>(LLADDR(sdl));

      // Skip all-zero MACs (invalid/unconfigured)
      bool all_zero = true;
      for (int i = 0; i < 6; i++) {
        if (mac[i] != 0) {
          all_zero = false;
          break;
        }
      }
      if (all_zero) continue;

      // Copy the MAC address
      memcpy(node, mac, 6);
      found = true;
      break;
    }
#else
    // On Linux, hardware addresses are in AF_PACKET family
    if (ifa->ifa_addr->sa_family == AF_PACKET) {
      struct sockaddr_ll* sll =
          reinterpret_cast<struct sockaddr_ll*>(ifa->ifa_addr);

      // Skip if not Ethernet
      if (sll->sll_hatype != ARPHRD_ETHER || sll->sll_halen != 6) continue;

      // Skip loopback interfaces
      if (ifa->ifa_flags & IFF_LOOPBACK) continue;

      // Skip all-zero MACs (invalid/unconfigured)
      bool all_zero = true;
      for (int i = 0; i < 6; i++) {
        if (sll->sll_addr[i] != 0) {
          all_zero = false;
          break;
        }
      }
      if (all_zero) continue;

      // Copy the MAC address
      memcpy(node, sll->sll_addr, 6);
      found = true;
      break;
    }
#endif
  }

  freeifaddrs(ifap);
  return found;
}

// Helper function to get MAC address (tries real MAC, falls back to random)
static void get_node_id(unsigned char node[6], bool force_random = false) {
  static std::random_device rd;
  static std::mt19937 gen(rd());
  static std::uniform_int_distribution<uint8_t> dis(0, 255);

  if (force_random) {
    // Generate random multicast MAC (set multicast bit)
    for (int i = 0; i < 6; i++) {
      node[i] = dis(gen);
    }
    node[0] |= 0x01;  // Set multicast bit
  } else {
    // Try to get real MAC address
    if (!get_real_mac_address(node)) {
      // Fallback to random MAC with locally administered bit set
      for (int i = 0; i < 6; i++) {
        node[i] = dis(gen);
      }
      node[0] |= 0x02;  // Set locally administered bit
    }
  }
}

// Helper function to get current timestamp for UUID v1
static uint64_t get_uuid_timestamp() {
  // UUID timestamp is 100-nanosecond intervals since 1582-10-15 00:00:00 UTC
  // Unix epoch is 1970-01-01, so we need to add the difference
  const uint64_t uuid_epoch_offset = 0x01B21DD213814000ULL;

  auto now = std::chrono::system_clock::now();
  auto duration = now.time_since_epoch();
  auto microseconds =
      std::chrono::duration_cast<std::chrono::microseconds>(duration);

  // Convert microseconds to 100-nanosecond intervals and add epoch offset
  uint64_t timestamp = (microseconds.count() * 10) + uuid_epoch_offset;

  return timestamp;
}

bool generate_uuid_v1(unsigned char* binary_uuid, bool use_random_mac) {
  if (!binary_uuid) return false;

  static std::random_device rd;
  static std::mt19937 gen(rd());
  static std::uniform_int_distribution<uint16_t> clock_dis(0, 0x3FFF);
  static uint16_t clock_seq = clock_dis(gen);

  uint64_t timestamp = get_uuid_timestamp();
  unsigned char node[6];
  get_node_id(node, use_random_mac);

  // Layout UUID v1 fields
  // time_low (32 bits)
  binary_uuid[0] = (timestamp >> 24) & 0xFF;
  binary_uuid[1] = (timestamp >> 16) & 0xFF;
  binary_uuid[2] = (timestamp >> 8) & 0xFF;
  binary_uuid[3] = timestamp & 0xFF;

  // time_mid (16 bits)
  binary_uuid[4] = (timestamp >> 40) & 0xFF;
  binary_uuid[5] = (timestamp >> 32) & 0xFF;

  // time_hi_and_version (16 bits)
  uint16_t time_hi = (timestamp >> 48) & 0x0FFF;
  binary_uuid[6] = (time_hi >> 8) & 0xFF;
  binary_uuid[7] = time_hi & 0xFF;
  binary_uuid[6] |= 0x10;  // Set version 1

  // clock_seq_hi_and_reserved (8 bits)
  binary_uuid[8] = (clock_seq >> 8) & 0x3F;
  binary_uuid[8] |= 0x80;  // Set variant bits (10)

  // clock_seq_low (8 bits)
  binary_uuid[9] = clock_seq & 0xFF;

  // node (48 bits)
  memcpy(&binary_uuid[10], node, 6);

  return true;
}

bool generate_uuid_v4(unsigned char* binary_uuid) {
  if (!binary_uuid) return false;

  // Generate 128 bits (16 bytes) of cryptographically secure random data
  if (RAND_bytes(binary_uuid, 16) != 1) {
    // Failed to generate random bytes
    return false;
  }

  // Set version (4) and variant bits according to RFC 9562
  binary_uuid[6] =
      (binary_uuid[6] & 0x0F) | 0x40;  // Version 4 (bits 4-7 of byte 6)
  binary_uuid[8] =
      (binary_uuid[8] & 0x3F) | 0x80;  // Variant 10 (bits 6-7 of byte 8)

  return true;
}

bool generate_uuid_v3(const unsigned char* namespace_uuid, const char* name,
                      size_t name_len, unsigned char* binary_uuid) {
  if (!namespace_uuid || !name || !binary_uuid) return false;

  unsigned char digest[16];
  unsigned int digest_len = 0;

  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) return false;
  EVP_DigestInit_ex(ctx, EVP_md5(), nullptr);
  EVP_DigestUpdate(ctx, namespace_uuid, 16);
  EVP_DigestUpdate(ctx, name, name_len);
  EVP_DigestFinal_ex(ctx, digest, &digest_len);
  EVP_MD_CTX_free(ctx);

  // Copy digest to UUID
  memcpy(binary_uuid, digest, 16);

  // Set version (3) and variant bits
  binary_uuid[6] = (binary_uuid[6] & 0x0F) | 0x30;  // Version 3
  binary_uuid[8] = (binary_uuid[8] & 0x3F) | 0x80;  // Variant 10

  return true;
}

bool generate_uuid_v5(const unsigned char* namespace_uuid, const char* name,
                      size_t name_len, unsigned char* binary_uuid) {
  if (!namespace_uuid || !name || !binary_uuid) return false;

  unsigned char digest[20];
  unsigned int digest_len = 0;

  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) return false;
  EVP_DigestInit_ex(ctx, EVP_sha1(), nullptr);
  EVP_DigestUpdate(ctx, namespace_uuid, 16);
  EVP_DigestUpdate(ctx, name, name_len);
  EVP_DigestFinal_ex(ctx, digest, &digest_len);
  EVP_MD_CTX_free(ctx);

  // Copy first 16 bytes of SHA1 digest to UUID
  memcpy(binary_uuid, digest, 16);

  // Set version (5) and variant bits
  binary_uuid[6] = (binary_uuid[6] & 0x0F) | 0x50;  // Version 5
  binary_uuid[8] = (binary_uuid[8] & 0x3F) | 0x80;  // Variant 10

  return true;
}

bool generate_uuid_v6(unsigned char* binary_uuid, bool use_random_mac) {
  if (!binary_uuid) return false;

  static std::random_device rd;
  static std::mt19937 gen(rd());
  static std::uniform_int_distribution<uint16_t> clock_dis(0, 0x3FFF);
  static uint16_t clock_seq = clock_dis(gen);

  uint64_t timestamp = get_uuid_timestamp();
  unsigned char node[6];
  get_node_id(node, use_random_mac);

  // UUID v6 layout: timestamp bits in high-to-low order for lexicographic sorting
  // time_high (bits 59..28) -> bytes 0-3
  binary_uuid[0] = (timestamp >> 52) & 0xFF;
  binary_uuid[1] = (timestamp >> 44) & 0xFF;
  binary_uuid[2] = (timestamp >> 36) & 0xFF;
  binary_uuid[3] = (timestamp >> 28) & 0xFF;

  // time_mid (bits 27..12) -> bytes 4-5
  binary_uuid[4] = (timestamp >> 20) & 0xFF;
  binary_uuid[5] = (timestamp >> 12) & 0xFF;

  // time_low (bits 11..0) -> bytes 6-7 with version in high nibble
  binary_uuid[6] = ((timestamp >> 8) & 0x0F) | 0x60;  // Version 6
  binary_uuid[7] = timestamp & 0xFF;

  // clock_seq_hi_and_reserved (8 bits)
  binary_uuid[8] = ((clock_seq >> 8) & 0x3F) | 0x80;  // Variant 10

  // clock_seq_low (8 bits)
  binary_uuid[9] = clock_seq & 0xFF;

  // node (48 bits)
  memcpy(&binary_uuid[10], node, 6);

  return true;
}

bool generate_uuid_v7(unsigned char* binary_uuid) {
  if (!binary_uuid) return false;

  // Get Unix timestamp in milliseconds
  auto now = std::chrono::system_clock::now();
  auto duration = now.time_since_epoch();
  uint64_t unix_ts_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();

  // Generate random bytes for the rest
  if (RAND_bytes(binary_uuid, 16) != 1) {
    return false;
  }

  // Unix timestamp in milliseconds (48 bits, big-endian) -> bytes 0-5
  binary_uuid[0] = (unix_ts_ms >> 40) & 0xFF;
  binary_uuid[1] = (unix_ts_ms >> 32) & 0xFF;
  binary_uuid[2] = (unix_ts_ms >> 24) & 0xFF;
  binary_uuid[3] = (unix_ts_ms >> 16) & 0xFF;
  binary_uuid[4] = (unix_ts_ms >> 8) & 0xFF;
  binary_uuid[5] = unix_ts_ms & 0xFF;

  // Set version (7) and variant bits
  binary_uuid[6] = (binary_uuid[6] & 0x0F) | 0x70;  // Version 7
  binary_uuid[8] = (binary_uuid[8] & 0x3F) | 0x80;  // Variant 10

  return true;
}

}  // namespace uuid_funcs

using namespace uuid_funcs;

// =============================================================================
// UUID Type Functions (encode, decode, compare)
// =============================================================================

// Encode: string -> binary (16 bytes)
bool uuid_encode(unsigned char* buffer, size_t buffer_size,
                 const char* from, size_t from_len, size_t* length) {
  if (buffer_size < kUuidBinarySize) {
    return true;  // error
  }

  if (!parse_uuid_string(from, from_len, buffer)) {
    return true;  // error - invalid UUID format
  }

  *length = kUuidBinarySize;
  return false;  // success
}

// Decode: binary -> string (36 chars)
bool uuid_decode(const unsigned char* buffer, size_t buffer_size,
                 char* to, size_t to_size, size_t* to_length) {
  if (buffer_size < kUuidBinarySize || to_size < kUuidStringMaxLength) {
    return true;  // error
  }

  static const char hex_chars[] = "0123456789abcdef";
  size_t pos = 0;

  for (size_t i = 0; i < kUuidBinarySize; ++i) {
    unsigned char byte = buffer[i];
    to[pos++] = hex_chars[byte >> 4];
    to[pos++] = hex_chars[byte & 0x0F];

    // Add hyphens at positions 4, 6, 8, 10 (after bytes 3, 5, 7, 9)
    if (i == 3 || i == 5 || i == 7 || i == 9) {
      to[pos++] = '-';
    }
  }

  *to_length = kUuidStringMaxLength;
  return false;  // success
}

// Compare: lexicographic comparison of binary UUIDs
int uuid_compare(const unsigned char* data1, size_t len1,
                 const unsigned char* data2, size_t len2) {
  // Both UUIDs should be exactly 16 bytes
  if (len1 != kUuidBinarySize || len2 != kUuidBinarySize) {
    // Handle error case - treat shorter UUID as "less"
    if (len1 != len2) {
      return (len1 < len2) ? -1 : 1;
    }
  }

  return memcmp(data1, data2, kUuidBinarySize);
}

// =============================================================================
// VDF Implementations
// =============================================================================

// Helper to copy binary UUID to binary result buffer
static void copy_uuid_to_binary_result(const unsigned char* binary_uuid,
                                       vef_vdf_result_t* result) {
  memcpy(result->bin_buf, binary_uuid, kUuidBinarySize);
  result->type = VEF_RESULT_VALUE;
  result->actual_len = kUuidBinarySize;
}

// uuid_generate_v1() - time-based UUID with MAC address, returns UUID type
void uuid_generate_v1_impl(vef_context_t* ctx, vef_vdf_result_t* result) {
  unsigned char binary_uuid[kUuidBinarySize];

  if (!generate_uuid_v1(binary_uuid, false)) {
    result->type = VEF_RESULT_ERROR;
    strcpy(result->error_msg, "Failed to generate UUID v1");
    return;
  }

  copy_uuid_to_binary_result(binary_uuid, result);
}

// uuid_generate_v1mc() - time-based UUID with random multicast MAC, returns UUID type
void uuid_generate_v1mc_impl(vef_context_t* ctx, vef_vdf_result_t* result) {
  unsigned char binary_uuid[kUuidBinarySize];

  if (!generate_uuid_v1(binary_uuid, true)) {
    result->type = VEF_RESULT_ERROR;
    strcpy(result->error_msg, "Failed to generate UUID v1mc");
    return;
  }

  copy_uuid_to_binary_result(binary_uuid, result);
}

// uuid_generate_v3(namespace, name) - MD5-based name UUID, returns UUID type
void uuid_generate_v3_impl(vef_context_t* ctx,
                           vef_invalue_t* ns_arg, vef_invalue_t* name_arg,
                           vef_vdf_result_t* result) {
  if (ns_arg->is_null || name_arg->is_null) {
    result->type = VEF_RESULT_NULL;
    return;
  }

  // Parse namespace UUID from string
  unsigned char namespace_binary[kUuidBinarySize];
  if (!parse_uuid_string(ns_arg->str_value, ns_arg->str_len, namespace_binary)) {
    result->type = VEF_RESULT_ERROR;
    strcpy(result->error_msg, "Invalid namespace UUID format");
    return;
  }

  // Generate UUID v3
  unsigned char binary_uuid[kUuidBinarySize];
  if (!generate_uuid_v3(namespace_binary, name_arg->str_value, name_arg->str_len,
                        binary_uuid)) {
    result->type = VEF_RESULT_ERROR;
    strcpy(result->error_msg, "Failed to generate UUID v3");
    return;
  }

  copy_uuid_to_binary_result(binary_uuid, result);
}

// uuid_generate_v4() - random UUID, returns UUID type
void uuid_generate_v4_impl(vef_context_t* ctx, vef_vdf_result_t* result) {
  unsigned char binary_uuid[kUuidBinarySize];

  if (!generate_uuid_v4(binary_uuid)) {
    result->type = VEF_RESULT_ERROR;
    strcpy(result->error_msg, "Failed to generate UUID v4");
    return;
  }

  copy_uuid_to_binary_result(binary_uuid, result);
}

// uuid_generate_v5(namespace, name) - SHA1-based name UUID, returns UUID type
void uuid_generate_v5_impl(vef_context_t* ctx,
                           vef_invalue_t* ns_arg, vef_invalue_t* name_arg,
                           vef_vdf_result_t* result) {
  if (ns_arg->is_null || name_arg->is_null) {
    result->type = VEF_RESULT_NULL;
    return;
  }

  // Parse namespace UUID from string
  unsigned char namespace_binary[kUuidBinarySize];
  if (!parse_uuid_string(ns_arg->str_value, ns_arg->str_len, namespace_binary)) {
    result->type = VEF_RESULT_ERROR;
    strcpy(result->error_msg, "Invalid namespace UUID format");
    return;
  }

  // Generate UUID v5
  unsigned char binary_uuid[kUuidBinarySize];
  if (!generate_uuid_v5(namespace_binary, name_arg->str_value, name_arg->str_len,
                        binary_uuid)) {
    result->type = VEF_RESULT_ERROR;
    strcpy(result->error_msg, "Failed to generate UUID v5");
    return;
  }

  copy_uuid_to_binary_result(binary_uuid, result);
}

// UUID_V6() - time-ordered UUID (reordered v1), returns UUID type
void uuid_generate_v6_impl(vef_context_t* ctx, vef_vdf_result_t* result) {
  unsigned char binary_uuid[kUuidBinarySize];

  if (!generate_uuid_v6(binary_uuid, false)) {
    result->type = VEF_RESULT_ERROR;
    strcpy(result->error_msg, "Failed to generate UUID v6");
    return;
  }

  copy_uuid_to_binary_result(binary_uuid, result);
}

// UUID_V7() - Unix epoch time-ordered UUID, returns UUID type
void uuid_generate_v7_impl(vef_context_t* ctx, vef_vdf_result_t* result) {
  unsigned char binary_uuid[kUuidBinarySize];

  if (!generate_uuid_v7(binary_uuid)) {
    result->type = VEF_RESULT_ERROR;
    strcpy(result->error_msg, "Failed to generate UUID v7");
    return;
  }

  copy_uuid_to_binary_result(binary_uuid, result);
}

// UUID_VERSION(str) - extracts version number from UUID string
void uuid_version_impl(vef_context_t* ctx,
                       vef_invalue_t* arg,
                       vef_vdf_result_t* result) {
  if (arg->is_null) {
    result->type = VEF_RESULT_NULL;
    return;
  }

  unsigned char binary_uuid[kUuidBinarySize];
  if (!parse_uuid_string(arg->str_value, arg->str_len, binary_uuid)) {
    result->type = VEF_RESULT_NULL;
    return;
  }

  result->type = VEF_RESULT_VALUE;
  result->int_value = (binary_uuid[6] >> 4) & 0x0F;
}

// UUID_TIMESTAMP(str) - extracts timestamp from v1/v6/v7 UUID as datetime string
void uuid_timestamp_impl(vef_context_t* ctx,
                         vef_invalue_t* arg,
                         vef_vdf_result_t* result) {
  if (arg->is_null) {
    result->type = VEF_RESULT_NULL;
    return;
  }

  unsigned char binary_uuid[kUuidBinarySize];
  if (!parse_uuid_string(arg->str_value, arg->str_len, binary_uuid)) {
    result->type = VEF_RESULT_NULL;
    return;
  }

  int version = (binary_uuid[6] >> 4) & 0x0F;
  time_t unix_seconds;

  if (version == 1) {
    // v1: Extract 60-bit timestamp from v1 layout
    uint64_t time_low = (static_cast<uint64_t>(binary_uuid[0]) << 24) |
                        (static_cast<uint64_t>(binary_uuid[1]) << 16) |
                        (static_cast<uint64_t>(binary_uuid[2]) << 8) |
                        static_cast<uint64_t>(binary_uuid[3]);
    uint64_t time_mid = (static_cast<uint64_t>(binary_uuid[4]) << 8) |
                        static_cast<uint64_t>(binary_uuid[5]);
    uint64_t time_hi = (static_cast<uint64_t>(binary_uuid[6] & 0x0F) << 8) |
                       static_cast<uint64_t>(binary_uuid[7]);
    uint64_t timestamp = (time_hi << 48) | (time_mid << 32) | time_low;

    const uint64_t uuid_epoch_offset = 0x01B21DD213814000ULL;
    if (timestamp < uuid_epoch_offset) {
      result->type = VEF_RESULT_NULL;
      return;
    }
    unix_seconds =
        static_cast<time_t>((timestamp - uuid_epoch_offset) / 10000000ULL);

  } else if (version == 6) {
    // v6: Extract 60-bit timestamp from reordered layout (high bits first)
    uint64_t timestamp =
        (static_cast<uint64_t>(binary_uuid[0]) << 52) |
        (static_cast<uint64_t>(binary_uuid[1]) << 44) |
        (static_cast<uint64_t>(binary_uuid[2]) << 36) |
        (static_cast<uint64_t>(binary_uuid[3]) << 28) |
        (static_cast<uint64_t>(binary_uuid[4]) << 20) |
        (static_cast<uint64_t>(binary_uuid[5]) << 12) |
        (static_cast<uint64_t>(binary_uuid[6] & 0x0F) << 8) |
        static_cast<uint64_t>(binary_uuid[7]);

    const uint64_t uuid_epoch_offset = 0x01B21DD213814000ULL;
    if (timestamp < uuid_epoch_offset) {
      result->type = VEF_RESULT_NULL;
      return;
    }
    unix_seconds =
        static_cast<time_t>((timestamp - uuid_epoch_offset) / 10000000ULL);

  } else if (version == 7) {
    // v7: Extract 48-bit Unix millisecond timestamp from bytes 0-5
    uint64_t unix_ts_ms =
        (static_cast<uint64_t>(binary_uuid[0]) << 40) |
        (static_cast<uint64_t>(binary_uuid[1]) << 32) |
        (static_cast<uint64_t>(binary_uuid[2]) << 24) |
        (static_cast<uint64_t>(binary_uuid[3]) << 16) |
        (static_cast<uint64_t>(binary_uuid[4]) << 8) |
        static_cast<uint64_t>(binary_uuid[5]);
    unix_seconds = static_cast<time_t>(unix_ts_ms / 1000);

  } else {
    result->type = VEF_RESULT_NULL;
    return;
  }

  struct tm tm_buf;
  if (gmtime_r(&unix_seconds, &tm_buf) == nullptr) {
    result->type = VEF_RESULT_NULL;
    return;
  }

  // Format into a local buffer first, then copy to result
  // (sizeof(result->str_buf) may not reflect the actual allocated size)
  char buf[20];  // "YYYY-MM-DD HH:MM:SS" + null = 20 bytes
  size_t len = strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_buf);
  if (len == 0) {
    result->type = VEF_RESULT_NULL;
    return;
  }

  memcpy(result->str_buf, buf, len);
  result->type = VEF_RESULT_VALUE;
  result->actual_len = len;
}

// UUID_EPOCH(str) - extracts Unix epoch timestamp (seconds since 1970) from v1/v6/v7 UUID
void uuid_epoch_impl(vef_context_t* ctx,
                     vef_invalue_t* arg,
                     vef_vdf_result_t* result) {
  if (arg->is_null) {
    result->type = VEF_RESULT_NULL;
    return;
  }

  unsigned char binary_uuid[kUuidBinarySize];
  if (!parse_uuid_string(arg->str_value, arg->str_len, binary_uuid)) {
    result->type = VEF_RESULT_NULL;
    return;
  }

  int version = (binary_uuid[6] >> 4) & 0x0F;
  int64_t unix_seconds;

  if (version == 1) {
    uint64_t time_low = (static_cast<uint64_t>(binary_uuid[0]) << 24) |
                        (static_cast<uint64_t>(binary_uuid[1]) << 16) |
                        (static_cast<uint64_t>(binary_uuid[2]) << 8) |
                        static_cast<uint64_t>(binary_uuid[3]);
    uint64_t time_mid = (static_cast<uint64_t>(binary_uuid[4]) << 8) |
                        static_cast<uint64_t>(binary_uuid[5]);
    uint64_t time_hi = (static_cast<uint64_t>(binary_uuid[6] & 0x0F) << 8) |
                       static_cast<uint64_t>(binary_uuid[7]);
    uint64_t timestamp = (time_hi << 48) | (time_mid << 32) | time_low;

    const uint64_t uuid_epoch_offset = 0x01B21DD213814000ULL;
    if (timestamp < uuid_epoch_offset) {
      result->type = VEF_RESULT_NULL;
      return;
    }
    unix_seconds =
        static_cast<int64_t>((timestamp - uuid_epoch_offset) / 10000000ULL);

  } else if (version == 6) {
    uint64_t timestamp =
        (static_cast<uint64_t>(binary_uuid[0]) << 52) |
        (static_cast<uint64_t>(binary_uuid[1]) << 44) |
        (static_cast<uint64_t>(binary_uuid[2]) << 36) |
        (static_cast<uint64_t>(binary_uuid[3]) << 28) |
        (static_cast<uint64_t>(binary_uuid[4]) << 20) |
        (static_cast<uint64_t>(binary_uuid[5]) << 12) |
        (static_cast<uint64_t>(binary_uuid[6] & 0x0F) << 8) |
        static_cast<uint64_t>(binary_uuid[7]);

    const uint64_t uuid_epoch_offset = 0x01B21DD213814000ULL;
    if (timestamp < uuid_epoch_offset) {
      result->type = VEF_RESULT_NULL;
      return;
    }
    unix_seconds =
        static_cast<int64_t>((timestamp - uuid_epoch_offset) / 10000000ULL);

  } else if (version == 7) {
    uint64_t unix_ts_ms =
        (static_cast<uint64_t>(binary_uuid[0]) << 40) |
        (static_cast<uint64_t>(binary_uuid[1]) << 32) |
        (static_cast<uint64_t>(binary_uuid[2]) << 24) |
        (static_cast<uint64_t>(binary_uuid[3]) << 16) |
        (static_cast<uint64_t>(binary_uuid[4]) << 8) |
        static_cast<uint64_t>(binary_uuid[5]);
    unix_seconds = static_cast<int64_t>(unix_ts_ms / 1000);

  } else {
    result->type = VEF_RESULT_NULL;
    return;
  }

  result->type = VEF_RESULT_VALUE;
  result->int_value = unix_seconds;
}

// uuid_compare(str1, str2) - compares two UUID strings, returns -1/0/1
void uuid_compare_impl(vef_context_t* ctx,
                       vef_invalue_t* arg1, vef_invalue_t* arg2,
                       vef_vdf_result_t* result) {
  if (arg1->is_null || arg2->is_null) {
    result->type = VEF_RESULT_NULL;
    return;
  }

  // Parse both UUID strings to binary
  unsigned char binary1[kUuidBinarySize];
  unsigned char binary2[kUuidBinarySize];

  if (!parse_uuid_string(arg1->str_value, arg1->str_len, binary1) ||
      !parse_uuid_string(arg2->str_value, arg2->str_len, binary2)) {
    result->type = VEF_RESULT_NULL;
    return;
  }

  // Compare the binary UUIDs
  int cmp = memcmp(binary1, binary2, kUuidBinarySize);

  result->type = VEF_RESULT_VALUE;
  result->int_value = (cmp < 0) ? -1 : (cmp > 0) ? 1 : 0;
}

// =============================================================================
// Extension Registration
// =============================================================================

VEF_GENERATE_ENTRY_POINTS(
  make_extension("vsql_uuid", "0.0.2")
    // UUID type definition
    .type(make_type(UUID)
      .persisted_length(kUuidBinarySize)
      .max_decode_buffer_length(kUuidStringMaxLength + 1)
      .encode(&uuid_encode)
      .decode(&uuid_decode)
      .compare(&uuid_compare)
      .build())

    // UUID generation functions - all return UUID type (binary)
    .func(make_func<&uuid_generate_v1_impl>("UUID_V1")
      .returns(UUID)
      .build())

    .func(make_func<&uuid_generate_v1mc_impl>("UUID_V1MC")
      .returns(UUID)
      .build())

    .func(make_func<&uuid_generate_v3_impl>("UUID_V3")
      .returns(UUID)
      .param(STRING)
      .param(STRING)
      .build())

    .func(make_func<&uuid_generate_v4_impl>("UUID_V4")
      .returns(UUID)
      .build())

    .func(make_func<&uuid_generate_v5_impl>("UUID_V5")
      .returns(UUID)
      .param(STRING)
      .param(STRING)
      .build())

    .func(make_func<&uuid_generate_v6_impl>("UUID_V6")
      .returns(UUID)
      .build())

    .func(make_func<&uuid_generate_v7_impl>("UUID_V7")
      .returns(UUID)
      .build())

    // UUID utility functions
    .func(make_func<&uuid_compare_impl>("UUID_COMPARE")
      .returns(INT)
      .param(STRING)
      .param(STRING)
      .build())

    .func(make_func<&uuid_version_impl>("UUID_VERSION")
      .returns(INT)
      .param(STRING)
      .build())

    .func(make_func<&uuid_timestamp_impl>("UUID_TIMESTAMP")
      .returns(STRING)
      .param(STRING)
      .buffer_size(20)
      .build())

    .func(make_func<&uuid_epoch_impl>("UUID_EPOCH")
      .returns(INT)
      .param(STRING)
      .build())
)
