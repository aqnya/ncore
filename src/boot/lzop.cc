#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <minilzo.h>
#include <vector>

namespace boot {
namespace {

constexpr uint32_t kHeaderHasFilter = 0x00000800;

const uint8_t kLzopMagic[9] = {0x89, 0x4c, 0x5a, 0x4f,
                              0x00, 0x0d, 0x0a, 0x1a, 0x0a};

bool write_all(FILE *fp, const void *data, size_t size) {
  return size == 0 || fwrite(data, 1, size, fp) == size;
}

uint16_t read_be16(const uint8_t *p) {
  return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

uint32_t read_be32(const uint8_t *p) {
  return (static_cast<uint32_t>(p[0]) << 24) |
         (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

// Skip the lzop file header, mirroring the Linux kernel's parse_header().
// Returns the offset just past the header, or `false` if truncated/invalid.
bool parse_header(const uint8_t *data, size_t size, size_t &offset) {
  if (size < 9 || std::memcmp(data, kLzopMagic, sizeof(kLzopMagic)) != 0)
    return false;

  const uint8_t *p = data + 9;
  const uint8_t *end = data + size;

  // version (2) + library version (2) + extract version (2) + method (1)
  if (static_cast<size_t>(end - p) < 7)
    return false;

  const uint16_t version = read_be16(p);
  p += 7; // version(2) + library version(2) + extract version(2) + method(1)

  if (version >= 0x0940) {
    if (p >= end)
      return false;
    ++p; // compression level
  }

  if (static_cast<size_t>(end - p) < 4)
    return false;
  const bool has_filter = (read_be32(p) & kHeaderHasFilter) != 0;

  // flags (4) + mode (4) + mtime_low (4)
  if (static_cast<size_t>(end - p) < 12)
    return false;
  p += 12;
  if (has_filter) {
    if (static_cast<size_t>(end - p) < 4)
      return false;
    p += 4; // filter info
  }

  if (version >= 0x0940) {
    if (static_cast<size_t>(end - p) < 4)
      return false;
    p += 4; // mtime_high
  }

  if (p >= end)
    return false;
  const uint8_t name_len = *p++;
  // file name + checksum
  if (static_cast<size_t>(end - p) < static_cast<size_t>(name_len) + 4)
    return false;
  p += static_cast<size_t>(name_len) + 4;

  offset = static_cast<size_t>(p - data);
  return true;
}

} // namespace

bool decompress_lzop(const char *filepath, const uint8_t *data, size_t size) {
  if (lzo_init() != LZO_E_OK) {
    std::cerr << "lzop: lzo_init failed\n";
    return false;
  }

  size_t offset = 0;
  if (!parse_header(data, size, offset)) {
    std::cerr << "lzop: invalid header\n";
    return false;
  }

  FILE *out = fopen(filepath, "wb");
  if (!out) {
    std::cerr << "lzop: fopen failed: " << filepath << '\n';
    return false;
  }

  const uint8_t *p = data + offset;
  const uint8_t *end = data + size;

  std::vector<uint8_t> out_buf(256 << 10);
  bool ok = false;

  while (p < end) {
    if (static_cast<size_t>(end - p) < 4) {
      std::cerr << "lzop: truncated block size\n";
      break;
    }

    const uint32_t dst_len = read_be32(p);
    p += 4;

    if (dst_len == 0) {
      ok = true;
      break;
    }

    if (static_cast<size_t>(end - p) < 8) {
      std::cerr << "lzop: truncated block\n";
      break;
    }

    const uint32_t src_len = read_be32(p);
    p += 8; // compressed size + block checksum

    if (src_len == 0 || src_len > dst_len) {
      std::cerr << "lzop: corrupt block (src " << src_len << ", dst " << dst_len
                << ")\n";
      break;
    }

    if (static_cast<size_t>(end - p) < src_len) {
      std::cerr << "lzop: truncated block data\n";
      break;
    }

    if (out_buf.size() < dst_len)
      out_buf.resize(dst_len);

    if (dst_len == src_len) {
      // Stored uncompressed block.
      std::memcpy(out_buf.data(), p, src_len);
    } else {
      lzo_uint decoded = dst_len;
      const int ret =
          lzo1x_decompress_safe(p, src_len, out_buf.data(), &decoded, nullptr);
      if (ret != LZO_E_OK || decoded != dst_len) {
        std::cerr << "lzop: lzo1x_decompress_safe failed: " << ret << '\n';
        break;
      }
    }

    if (!write_all(out, out_buf.data(), dst_len))
      break;

    p += src_len;
  }

  if (fclose(out) != 0) {
    std::cerr << "lzop: fclose failed: " << filepath << '\n';
    return false;
  }

  return ok;
}

} // namespace boot
