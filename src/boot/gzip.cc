#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <vector>
#include <zlib.h>

namespace boot {
namespace {

constexpr size_t kBufferSize = 64 << 10;

bool write_all(FILE *fp, const void *data, size_t size) {
  return size == 0 || fwrite(data, 1, size, fp) == size;
}

// Inflate a gzip stream (possibly multiple concatenated members) into `out`.
bool inflate_gzip(const uint8_t *data, size_t size, FILE *out) {
  z_stream strm{};
  if (inflateInit2(&strm, 15 + 16) != Z_OK) {
    std::cerr << "gzip: inflateInit2 failed\n";
    return false;
  }

  std::vector<uint8_t> buffer(kBufferSize);
  strm.next_in = const_cast<Bytef *>(data);
  strm.avail_in = static_cast<uInt>(size);

  bool ok = false;

  while (true) {
    strm.next_out = buffer.data();
    strm.avail_out = static_cast<uInt>(buffer.size());

    const int ret = inflate(&strm, Z_NO_FLUSH);

    if (!write_all(out, buffer.data(), buffer.size() - strm.avail_out))
      break;

    if (ret == Z_STREAM_END) {
      // A gzip file may hold several concatenated members.
      if (strm.avail_in == 0) {
        ok = true;
        break;
      }
      if (inflateReset2(&strm, 15 + 16) != Z_OK)
        break;
      continue;
    }

    if (ret == Z_BUF_ERROR && strm.avail_out != 0) {
      if (strm.avail_in == 0)
        break;
    }

    if (ret != Z_OK) {
      std::cerr << "gzip: inflate failed: " << (strm.msg ? strm.msg : "?")
                << '\n';
      break;
    }
  }

  inflateEnd(&strm);
  return ok;
}

} // namespace

bool decompress_gzip(const char *filepath, const uint8_t *data, size_t size) {
  if (size < 2) {
    std::cerr << "gzip: truncated header\n";
    return false;
  }

  // gzip2 ("\x1f\x9e", produced by e.g. Magisk's zopfli) shares the gzip
  // container layout but carries a different second magic byte. Patch a copy
  // so zlib accepts it as a regular gzip stream.
  std::vector<uint8_t> patched;
  if (data[0] == 0x1f && data[1] == 0x9e) {
    patched.assign(data, data + size);
    patched[1] = 0x8b;
    data = patched.data();
  }

  FILE *out = fopen(filepath, "wb");
  if (!out) {
    std::cerr << "gzip: fopen failed: " << filepath << '\n';
    return false;
  }

  const bool ok = inflate_gzip(data, size, out);

  if (fclose(out) != 0) {
    std::cerr << "gzip: fclose failed: " << filepath << '\n';
    return false;
  }

  return ok;
}

bool compress_gzip(const char *filepath, const uint8_t *data, size_t size) {
  FILE *out = fopen(filepath, "wb");
  if (!out) {
    std::cerr << "gzip: fopen failed: " << filepath << '\n';
    return false;
  }

  z_stream strm{};
  if (deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8,
                   Z_DEFAULT_STRATEGY) != Z_OK) {
    std::cerr << "gzip: deflateInit2 failed\n";
    fclose(out);
    return false;
  }

  std::vector<uint8_t> buffer(kBufferSize);
  strm.next_in = const_cast<Bytef *>(data);
  strm.avail_in = static_cast<uInt>(size);

  bool ok = false;

  while (true) {
    strm.next_out = buffer.data();
    strm.avail_out = static_cast<uInt>(buffer.size());

    const int ret = deflate(&strm, Z_FINISH);

    if (!write_all(out, buffer.data(), buffer.size() - strm.avail_out))
      break;

    if (ret == Z_STREAM_END) {
      ok = true;
      break;
    }

    if (ret != Z_OK && ret != Z_BUF_ERROR) {
      std::cerr << "gzip: deflate failed: " << (strm.msg ? strm.msg : "?")
                << '\n';
      break;
    }
  }

  deflateEnd(&strm);

  if (fclose(out) != 0) {
    std::cerr << "gzip: fclose failed: " << filepath << '\n';
    return false;
  }

  return ok;
}

} // namespace boot
