#include <bzlib.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <vector>

namespace boot {
namespace {

constexpr size_t kBufferSize = 64 << 10;

bool write_all(FILE *fp, const void *data, size_t size) {
  return size == 0 || fwrite(data, 1, size, fp) == size;
}

const char *bz2_error(int err) {
  switch (err) {
  case BZ_SEQUENCE_ERROR:
    return "sequence error";
  case BZ_PARAM_ERROR:
    return "parameter error";
  case BZ_MEM_ERROR:
    return "out of memory";
  case BZ_DATA_ERROR:
    return "data integrity error";
  case BZ_DATA_ERROR_MAGIC:
    return "bad magic";
  case BZ_IO_ERROR:
    return "io error";
  case BZ_UNEXPECTED_EOF:
    return "unexpected eof";
  case BZ_OUTBUFF_FULL:
    return "output buffer full";
  case BZ_CONFIG_ERROR:
    return "config error";
  default:
    return "unknown error";
  }
}

} // namespace

bool decompress_bzip2(const char *filepath, const uint8_t *data, size_t size) {
  FILE *out = fopen(filepath, "wb");
  if (!out) {
    std::cerr << "bzip2: fopen failed: " << filepath << '\n';
    return false;
  }

  bz_stream strm{};
  if (BZ2_bzDecompressInit(&strm, 0, 0) != BZ_OK) {
    std::cerr << "bzip2: BZ2_bzDecompressInit failed\n";
    fclose(out);
    return false;
  }

  std::vector<char> buffer(kBufferSize);
  strm.next_in = const_cast<char *>(reinterpret_cast<const char *>(data));
  strm.avail_in = static_cast<unsigned int>(size);

  bool ok = false;

  while (true) {
    strm.next_out = buffer.data();
    strm.avail_out = static_cast<unsigned int>(buffer.size());

    const int ret = BZ2_bzDecompress(&strm);

    const size_t produced = buffer.size() - strm.avail_out;
    if (!write_all(out, buffer.data(), produced))
      break;

    if (ret == BZ_STREAM_END) {
      ok = true;
      break;
    }

    if (ret != BZ_OK) {
      std::cerr << "bzip2: decompress failed: " << bz2_error(ret) << '\n';
      break;
    }

    if (strm.avail_in == 0 && produced == 0) {
      std::cerr << "bzip2: truncated stream\n";
      break;
    }
  }

  BZ2_bzDecompressEnd(&strm);

  if (fclose(out) != 0) {
    std::cerr << "bzip2: fclose failed: " << filepath << '\n';
    return false;
  }

  return ok;
}

bool compress_bzip2(const char *filepath, const uint8_t *data, size_t size) {
  // bzip2 works on a single in-memory buffer for the streaming helpers used
  // here, so bound the output conservatively (worst case is slightly larger
  // than the input).
  unsigned int dest_len = static_cast<unsigned int>(size + size / 100 + 600);

  std::vector<char> out_buf(dest_len);

  const int ret =
      BZ2_bzBuffToBuffCompress(out_buf.data(), &dest_len,
                               const_cast<char *>(reinterpret_cast<const char *>(
                                   data)),
                               static_cast<unsigned int>(size), 9, 0, 0);
  if (ret != BZ_OK) {
    std::cerr << "bzip2: compress failed: " << bz2_error(ret) << '\n';
    return false;
  }

  FILE *out = fopen(filepath, "wb");
  if (!out) {
    std::cerr << "bzip2: fopen failed: " << filepath << '\n';
    return false;
  }

  const bool ok = write_all(out, out_buf.data(), dest_len);

  if (fclose(out) != 0) {
    std::cerr << "bzip2: fclose failed: " << filepath << '\n';
    return false;
  }

  return ok;
}

} // namespace boot
