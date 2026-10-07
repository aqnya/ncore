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

bool decompress_lz4_legacy(const char *filepath, const uint8_t *data,
                           size_t size) {
  const uint8_t *p = data;
  const uint8_t *end = data + size;

  uint32_t magic;
  if (!read_u32(p, end, magic)) {
    std::cerr << "LZ4 legacy: truncated magic\n";
    return false;
  }

  if (magic != kLegacyMagic) {
    std::cerr << "LZ4 legacy: bad magic: 0x" << std::hex << magic << std::dec
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
      std::cerr << "LZ4 legacy: truncated block size\n";
      break;
    }

    if (block_size == 0) {
      // End marker.
      ok = true;
      break;
    }

    if (block_size > kLegacyBlockSize) {
      std::cerr << "LZ4 legacy: block too large: " << block_size << '\n';
      break;
    }

    if (static_cast<size_t>(end - p) < block_size) {
      std::cerr << "LZ4 legacy: truncated block\n";
      break;
    }

    std::memcpy(in.data(), p, block_size);
    p += block_size;

    const int decoded = LZ4_decompress_safe(in.data(), out_buf.data(),
                                            static_cast<int>(block_size),
                                            static_cast<int>(kLegacyBlockSize));

    if (decoded < 0) {
      std::cerr << "LZ4 legacy: decompression failed\n";
      break;
    }

    if (!write_all(out, out_buf.data(), decoded)) {
      std::cerr << "LZ4 legacy: fwrite failed\n";
      break;
    }
  }

  fclose(out);
  return ok;
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

} // namespace boot