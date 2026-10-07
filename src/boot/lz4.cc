#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <lz4.h>
#include <lz4frame.h>
#include <vector>

namespace boot {

namespace {

constexpr size_t kLegacyBlockSize = 8 << 20;
constexpr size_t kFrameBufferSize = 16 << 10;

constexpr uint32_t kLegacyMagic = 0x184C2102;
constexpr uint32_t kLgMagic = 0x184C2103;

bool write_all(FILE *fp, const void *data, size_t size) {
  return size == 0 || fwrite(data, 1, size, fp) == size;
}

bool read_u32(const uint8_t *&p, const uint8_t *end, uint32_t &value) {
  if (static_cast<size_t>(end - p) < sizeof(value))
    return false;

  std::memcpy(&value, p, sizeof(value));
  p += sizeof(value);
  return true;
}

} // namespace

// Shared decoder for the legacy LZ4 block format. `is_lg` selects the LG
// variant, which terminates with a little-endian u32 holding the total
// uncompressed size instead of a zero-sized block marker.
bool decompress_lz4_block(const char *filepath, const uint8_t *data,
                          size_t size, bool is_lg) {
  const uint8_t *p = data;
  const uint8_t *end = data + size;

  uint32_t magic;
  if (!read_u32(p, end, magic)) {
    std::cerr << "LZ4 block: truncated magic\n";
    return false;
  }

  if (magic != kLegacyMagic && magic != kLgMagic) {
    std::cerr << "LZ4 block: bad magic: 0x" << std::hex << magic << std::dec
              << '\n';
    return false;
  }

  FILE *out = fopen(filepath, "wb");
  if (!out) {
    std::cerr << "fopen failed: " << filepath << '\n';
    return false;
  }

  std::vector<char> in(kLegacyBlockSize);
  std::vector<char> out_buf(kLegacyBlockSize);

  bool ok = false;

  while (p < end) {
    uint32_t block_size;

    if (!read_u32(p, end, block_size)) {
      std::cerr << "LZ4 block: truncated block size\n";
      break;
    }

    if (block_size == 0) {
      // End marker (legacy format).
      ok = true;
      break;
    }

    if (block_size > kLegacyBlockSize) {
      // In the LG format the stream ends with the total uncompressed size,
      // which is never a valid compressed block. Treat it as EOF.
      if (is_lg) {
        ok = true;
        break;
      }
      std::cerr << "LZ4 block: block too large: " << block_size << '\n';
      break;
    }

    if (static_cast<size_t>(end - p) < block_size) {
      std::cerr << "LZ4 block: truncated block\n";
      break;
    }

    std::memcpy(in.data(), p, block_size);
    p += block_size;

    const int decoded = LZ4_decompress_safe(in.data(), out_buf.data(),
                                            static_cast<int>(block_size),
                                            static_cast<int>(kLegacyBlockSize));

    if (decoded < 0) {
      std::cerr << "LZ4 block: decompression failed\n";
      break;
    }

    if (!write_all(out, out_buf.data(), decoded)) {
      std::cerr << "LZ4 block: fwrite failed\n";
      break;
    }
  }

  if (fclose(out) != 0) {
    std::cerr << "LZ4 block: fclose failed: " << filepath << '\n';
    return false;
  }

  return ok;
}

bool decompress_lz4_legacy(const char *filepath, const uint8_t *data,
                           size_t size) {
  return decompress_lz4_block(filepath, data, size, false);
}

bool decompress_lz4_lg(const char *filepath, const uint8_t *data, size_t size) {
  return decompress_lz4_block(filepath, data, size, true);
}

bool decompress_lz4(const char *filepath, const uint8_t *data, size_t size) {
  FILE *out = fopen(filepath, "wb");
  if (!out) {
    std::cerr << "fopen failed: " << filepath << '\n';
    return false;
  }

  LZ4F_dctx *ctx = nullptr;

  size_t ret = LZ4F_createDecompressionContext(&ctx, LZ4F_VERSION);

  if (LZ4F_isError(ret)) {
    std::cerr << "LZ4F_createDecompressionContext: " << LZ4F_getErrorName(ret)
              << '\n';
    fclose(out);
    return false;
  }

  std::vector<uint8_t> buffer(kFrameBufferSize);

  const uint8_t *src = data;
  size_t remaining = size;

  bool ok = false;

  while (remaining > 0) {
    size_t src_size = remaining;
    size_t dst_size = buffer.size();

    ret =
        LZ4F_decompress(ctx, buffer.data(), &dst_size, src, &src_size, nullptr);

    if (LZ4F_isError(ret)) {
      std::cerr << "LZ4F_decompress: " << LZ4F_getErrorName(ret) << '\n';
      break;
    }

    if (!write_all(out, buffer.data(), dst_size)) {
      std::cerr << "LZ4F: fwrite failed\n";
      break;
    }

    src += src_size;
    remaining -= src_size;

    if (ret == 0) {
      ok = true;
      break;
    }

    if (src_size == 0 && dst_size == 0) {
      std::cerr << "LZ4F: decompression made no progress\n";
      break;
    }
  }

  LZ4F_freeDecompressionContext(ctx);
  fclose(out);

  return ok;
}

// Compress into the legacy/LG LZ4 block format, one block per 8 MiB chunk.
// `is_lg` picks the variant that terminates with a little-endian u32 holding
// the total uncompressed size (0x184C2103) instead of a zero end marker
// (0x184C2102).
bool compress_lz4_block(const char *filepath, const uint8_t *data, size_t size,
                        bool is_lg) {
  FILE *out = fopen(filepath, "wb");
  if (!out) {
    std::cerr << "fopen failed: " << filepath << '\n';
    return false;
  }

  auto write_le32 = [&](uint32_t value) {
    uint8_t buf[4] = {static_cast<uint8_t>(value),
                      static_cast<uint8_t>(value >> 8),
                      static_cast<uint8_t>(value >> 16),
                      static_cast<uint8_t>(value >> 24)};
    return write_all(out, buf, sizeof(buf));
  };

  const uint32_t magic = is_lg ? kLgMagic : kLegacyMagic;
  if (!write_le32(magic)) {
    std::cerr << "LZ4 block: fwrite failed\n";
    fclose(out);
    return false;
  }

  std::vector<char> out_buf(LZ4_compressBound(static_cast<int>(kLegacyBlockSize)));

  bool ok = true;
  size_t offset = 0;

  while (offset < size) {
    const size_t chunk = size - offset < kLegacyBlockSize
                             ? size - offset
                             : kLegacyBlockSize;

    const int compressed =
        LZ4_compress_default(reinterpret_cast<const char *>(data + offset),
                             out_buf.data(), static_cast<int>(chunk),
                             static_cast<int>(out_buf.size()));
    if (compressed <= 0) {
      std::cerr << "LZ4 block: compression failed\n";
      ok = false;
      break;
    }

    if (!write_le32(static_cast<uint32_t>(compressed)) ||
        !write_all(out, out_buf.data(), static_cast<size_t>(compressed))) {
      std::cerr << "LZ4 block: fwrite failed\n";
      ok = false;
      break;
    }

    offset += chunk;
  }

  if (ok) {
    // Legacy ends with a zero block; LG ends with the total uncompressed size.
    if (!write_le32(is_lg ? static_cast<uint32_t>(size) : 0)) {
      std::cerr << "LZ4 block: fwrite failed\n";
      ok = false;
    }
  }

  if (fclose(out) != 0) {
    std::cerr << "LZ4 block: fclose failed: " << filepath << '\n';
    return false;
  }

  return ok;
}

bool compress_lz4_legacy(const char *filepath, const uint8_t *data,
                         size_t size) {
  return compress_lz4_block(filepath, data, size, false);
}

bool compress_lz4(const char *filepath, const uint8_t *data, size_t size) {
  LZ4F_preferences_t prefs{};
  prefs.frameInfo.contentSize = size;

  LZ4F_cctx *ctx = nullptr;
  size_t ret = LZ4F_createCompressionContext(&ctx, LZ4F_VERSION);
  if (LZ4F_isError(ret)) {
    std::cerr << "LZ4F_createCompressionContext: " << LZ4F_getErrorName(ret)
              << '\n';
    return false;
  }

  FILE *out = fopen(filepath, "wb");
  if (!out) {
    std::cerr << "fopen failed: " << filepath << '\n';
    LZ4F_freeCompressionContext(ctx);
    return false;
  }

  const size_t bound = LZ4F_compressBound(kFrameBufferSize, &prefs);
  std::vector<uint8_t> out_buf(bound);

  bool ok = false;
  size_t offset = 0;

  do {
    size_t produced =
        LZ4F_compressBegin(ctx, out_buf.data(), out_buf.size(), &prefs);
    if (LZ4F_isError(produced)) {
      std::cerr << "LZ4F_compressBegin: " << LZ4F_getErrorName(produced) << '\n';
      break;
    }
    if (!write_all(out, out_buf.data(), produced))
      break;

    while (offset < size) {
      const size_t chunk = size - offset < kFrameBufferSize
                               ? size - offset
                               : kFrameBufferSize;
      produced = LZ4F_compressUpdate(ctx, out_buf.data(), out_buf.size(),
                                     data + offset, chunk, nullptr);
      if (LZ4F_isError(produced)) {
        std::cerr << "LZ4F_compressUpdate: " << LZ4F_getErrorName(produced)
                  << '\n';
        break;
      }
      if (!write_all(out, out_buf.data(), produced))
        break;
      offset += chunk;
    }

    if (offset < size)
      break;

    produced = LZ4F_compressEnd(ctx, out_buf.data(), out_buf.size(), nullptr);
    if (LZ4F_isError(produced)) {
      std::cerr << "LZ4F_compressEnd: " << LZ4F_getErrorName(produced) << '\n';
      break;
    }
    if (!write_all(out, out_buf.data(), produced))
      break;

    ok = true;
  } while (false);

  LZ4F_freeCompressionContext(ctx);

  if (fclose(out) != 0) {
    std::cerr << "LZ4F: fclose failed: " << filepath << '\n';
    return false;
  }

  return ok;
}

} // namespace boot