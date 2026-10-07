#include <iostream>
#include <lzma.h>
#include <string>
namespace boot {
namespace {
int init_decompress(lzma_stream *strm) {
  lzma_ret ret = lzma_stream_decoder(strm, UINT64_MAX, LZMA_CONCATENATED);
  if (ret == LZMA_OK)
    return 0;
  std::string msg;
  switch (ret) {
  case LZMA_MEM_ERROR:
    msg = "Memory allocation failed";
    break;

  case LZMA_OPTIONS_ERROR:
    msg = "Unsupported decompressor flags";
    break;

  default:
    msg = "Unknown error!";
    break;
  }

  std::cerr << "Error initializing the decoder: " << msg << "ret: " << ret
            << std::endl;
  return -1;
}
} // namespace

bool decompress_xz(const char *filepath, const uint8_t *data, size_t size) {
  lzma_stream strm = LZMA_STREAM_INIT;
  if (init_decompress(&strm) < 0)
    return false;

  FILE *outfile = fopen(filepath, "wb");
  if (!outfile) {
    fprintf(stderr, "Failed to open '%s': %s\n", filepath, strerror(errno));
    lzma_end(&strm);
    return false;
  }

  lzma_action action = LZMA_RUN;
  uint8_t outbuf[BUFSIZ];

  strm.next_in = data;
  strm.avail_in = size;
  strm.next_out = outbuf;
  strm.avail_out = sizeof(outbuf);

  bool ok = false;

  while (true) {
    if (strm.avail_in == 0)
      action = LZMA_FINISH;

    lzma_ret ret = lzma_code(&strm, action);

    if (strm.avail_out == 0 || ret == LZMA_STREAM_END) {
      size_t write_size = sizeof(outbuf) - strm.avail_out;
      if (fwrite(outbuf, 1, write_size, outfile) != write_size) {
        fprintf(stderr, "Write error: %s\n", strerror(errno));
        break;
      }
      strm.next_out = outbuf;
      strm.avail_out = sizeof(outbuf);
    }

    if (ret == LZMA_STREAM_END) {
      ok = true;
      break;
    }

    if (ret != LZMA_OK) {
      std::string msg;
      switch (ret) {
      case LZMA_MEM_ERROR:
        msg = "Memory allocation failed";
        break;
      case LZMA_FORMAT_ERROR:
        msg = "The input is not in the .xz format";
        break;
      case LZMA_OPTIONS_ERROR:
        msg = "Unsupported compression options";
        break;
      case LZMA_DATA_ERROR:
        msg = "Compressed file is corrupt";
        break;
      case LZMA_BUF_ERROR:
        msg = "Compressed file is truncated or otherwise corrupt";
        break;
      default:
        msg = "Unknown error, possibly a bug";
        break;
      }
      std::cerr << "Decoder error: " << msg << " (error code " << ret << ")\n";
      break;
    }
  }

  lzma_end(&strm);
  if (fclose(outfile) != 0) {
    fprintf(stderr, "Close error: %s\n", strerror(errno));
    return false;
  }
  return ok;
}
} // namespace boot