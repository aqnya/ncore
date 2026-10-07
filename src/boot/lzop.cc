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

bool compress_lzop(const char *filepath, const uint8_t *data, size_t size) {
  if (lzo_init() != LZO_E_OK) {
    std::cerr << "lzop: lzo_init failed\n";
    return false;
  }

  FILE *out = fopen(filepath, "wb");
  if (!out) {
    std::cerr << "lzop: fopen failed: " << filepath << '\n';
    return false;
  }

  auto put_be16 = [&](uint16_t value) {
    uint8_t buf[2] = {static_cast<uint8_t>(value >> 8),
                      static_cast<uint8_t>(value)};
    return write_all(out, buf, sizeof(buf));
  };
  auto put_be32 = [&](uint32_t value) {
    uint8_t buf[4] = {static_cast<uint8_t>(value >> 24),
                      static_cast<uint8_t>(value >> 16),
                      static_cast<uint8_t>(value >> 8),
                      static_cast<uint8_t>(value)};
    return write_all(out, buf, sizeof(buf));
  };

  // Minimal lzop header equivalent to `lzop -1 --no-name`. Fields mirror what
  // parse_header() in this file expects (version 0x0940, no filter, no name).
  bool ok = write_all(out, kLzopMagic, sizeof(kLzopMagic)) &&
            put_be16(0x0940) && // version
            put_be16(0x2060) && // library version (1.03)
            put_be16(0x0940);   // extract version

  const uint8_t method = 0x01; // LZO1X-1
  const uint8_t level = 3;     // compression level
  ok = ok && write_all(out, &method, 1) && write_all(out, &level, 1);

  ok = ok && put_be32(0) && // flags
       put_be32(0) &&       // mode
       put_be32(0) &&       // mtime_low
       put_be32(0);         // mtime_high (version >= 0x0940)

  const uint8_t name_len = 0; // no stored file name
  ok = ok && write_all(out, &name_len, 1) && put_be32(0); // header checksum

  if (!ok) {
    std::cerr << "lzop: failed to write header\n";
    fclose(out);
    return false;
  }

  std::vector<uint8_t> in_buf(256 << 10);
  std::vector<uint8_t> out_buf(in_buf.size() + in_buf.size() / 16 + 64 + 3);
  std::vector<uint8_t> work(LZO1X_1_MEM_COMPRESS);

  size_t offset = 0;
  bool stream_ok = true;

  while (offset < size) {
    const size_t chunk = size - offset < in_buf.size() ? size - offset
                                                       : in_buf.size();

    std::memcpy(in_buf.data(), data + offset, chunk);

    lzo_uint out_len = 0;
    const int ret = lzo1x_1_compress(in_buf.data(), chunk, out_buf.data(),
                                     &out_len, work.data());
    if (ret != LZO_E_OK) {
      std::cerr << "lzop: lzo1x_1_compress failed: " << ret << '\n';
      stream_ok = false;
      break;
    }

    // lzop uses a stored (uncompressed) block when compression does not help.
    if (out_len >= chunk) {
      out_len = chunk;
      std::memcpy(out_buf.data(), in_buf.data(), chunk);
    }

    if (!put_be32(static_cast<uint32_t>(chunk)) ||
        !put_be32(static_cast<uint32_t>(out_len)) ||
        !put_be32(0) || // uncompressed block checksum (0 to skip)
        !write_all(out, out_buf.data(), out_len)) {
      stream_ok = false;
      break;
    }

    offset += chunk;
  }

  if (stream_ok) {
    // Zero-length block terminates the stream.
    if (!put_be32(0)) {
      std::cerr << "lzop: failed to write end marker\n";
      stream_ok = false;
    }
  }

  if (fclose(out) != 0) {
    std::cerr << "lzop: fclose failed: " << filepath << '\n';
    return false;
  }

  return stream_ok;
}

} // namespace boot
