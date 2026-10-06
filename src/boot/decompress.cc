#include <cstdint>
#include <cstdio>
#include <iostream>
#include <lz4.h>
#include <lz4file.h>
#include <memory>
#include <vector>

namespace boot {

constexpr size_t BLOCK_SIZE = 8 << 20; // 8MB

bool decompress_lz4_legacy(const char *filepath, const uint8_t *data,
                           size_t size) {
  const uint8_t *p = data;
  const uint8_t *end = data + size;

  if (p + 4 > end) {
    std::cerr << "read magic failed" << std::endl;
    return false;
  }
  uint32_t magic;
  std::memcpy(&magic, p, 4);
  p += 4;
  if (magic != 0x184C2102) {
    std::cerr << "bad magic: 0x" << std::hex << magic << std::endl;
    return false;
  }
  FILE *out = fopen(filepath, "wb");

  std::vector<char> in_buf(LZ4_compressBound(BLOCK_SIZE));
  std::vector<char> out_buf(BLOCK_SIZE);

  while (p + 4 <= end) {
    uint32_t block_size;
    std::memcpy(&block_size, p, 4);
    p += 4;

    if (block_size == 0 || block_size > in_buf.size()) {
      return false;
    }
    if (p + block_size > end) {
      return false;
    }

    std::memcpy(in_buf.data(), p, block_size);
    p += block_size;

    int decoded = LZ4_decompress_safe(in_buf.data(), out_buf.data(), block_size,
                                      BLOCK_SIZE);
    if (decoded <= 0) {
      return false;
    }

    if (fwrite(out_buf.data(), 1, decoded, out) != (size_t)decoded) {
      return false;
    }

    if (decoded < BLOCK_SIZE) {
      break;
    }
  }
  return true;
}

constexpr size_t kBufferSize = 16 * 1024;

bool decompress_lz4(const char *filepath, const uint8_t *data, size_t size) {
  FILE *out_fd = fopen(filepath, "wb");
  if (!out_fd) {
    std::cerr << "fopen failed: " << filepath << std::endl;
    return false;
  }

  FILE *fp = fmemopen(const_cast<uint8_t *>(data), size, "rb");
  if (!fp) {
    std::cerr << "fmemopen failed" << std::endl;
    fclose(out_fd);
    return false;
  }

  std::unique_ptr<char[]> buffer;
  try {
    buffer = std::make_unique<char[]>(kBufferSize);
  } catch (const std::bad_alloc &) {
    std::cerr << "buffer alloc failed" << std::endl;
    fclose(fp);
    fclose(out_fd);
    return false;
  }

  LZ4_readFile_t *lz4fRead = nullptr;
  size_t ret = LZ4F_readOpen(&lz4fRead, fp);
  if (LZ4F_isError(ret)) {
    std::cerr << "LZ4F_readOpen error: " << LZ4F_getErrorName(ret) << std::endl;
    fclose(fp);
    fclose(out_fd);
    return false;
  }

  bool ok = true;
  while (true) {
    ret = LZ4F_read(lz4fRead, buffer.get(), kBufferSize);
    if (LZ4F_isError(ret)) {
      std::cerr << "LZ4F_read error: " << LZ4F_getErrorName(ret) << std::endl;
      ok = false;
      break;
    }
    if (ret == 0)
      break;
    if (fwrite(buffer.get(), 1, ret, out_fd) != ret) {
      std::cerr << "fwrite error" << std::endl;
      ok = false;
      break;
    }
  }

  LZ4F_readClose(lz4fRead);
  fclose(fp);
  fclose(out_fd);
  return ok;
}

} // namespace boot