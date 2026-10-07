#include <cstdint>
#include <cstdio>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

enum class boottype : uint8_t {
  boot_img_hdr_v0,
  boot_img_hdr_v1,
  boot_img_hdr_v2,
  boot_img_hdr_v3,
  boot_img_hdr_v4,
  vendor_boot_img_hdr_v3,
  vendor_boot_img_hdr_v4,
  invalid,
};

// Compression magics. The first two are only two bytes wide, so compare them
// as 16-bit values against the start of a section.
constexpr uint16_t GZIP1_MAGIC   = 0x8b1f; // "\x1f\x8b" (RFC 1952)
constexpr uint16_t GZIP2_MAGIC   = 0x9e1f; // "\x1f\x9e" (magiskboot gzip2)
constexpr uint32_t LZOP_MAGIC    = 0x4f5a4c89; // "\x89LZO"
constexpr uint32_t XZ_MAGIC      = 0x587a37fd; // "\xfd7zXZ"
constexpr uint32_t BZIP_MAGIC    = 0x685a42;   // "BZh" (3 bytes)
constexpr uint32_t LZ41_MAGIC    = 0x184c2103; // "\x03\x21\x4c\x18" (lz4_lg)
constexpr uint32_t LZ42_MAGIC    = 0x184d2204; // "\x04\x22\x4d\x18" (lz4 frame)
constexpr uint32_t LZ4_LEG_MAGIC = 0x184c2102; // "\x02\x21\x4c\x18" (lz4 legacy)

namespace boot {
class MMapFile {
public:
  explicit MMapFile(const char *path) {
    int fd = ::open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
      return;

    struct stat st{};
    if (::fstat(fd, &st) < 0 || st.st_size <= 0) {
      ::close(fd);
      fd = -1;
      return;
    }

    size_ = static_cast<size_t>(st.st_size);

    void *p = ::mmap(nullptr, size_, PROT_READ, MAP_PRIVATE, fd, 0);

    if (p == MAP_FAILED) {
      ::close(fd);
      fd = -1;
      size_ = 0;
      return;
    }

    data_ = static_cast<const uint8_t *>(p);

    ::close(fd);
    fd = -1;
  }

  ~MMapFile() {
    if (data_)
      ::munmap(const_cast<uint8_t *>(data_), size_);
  }

  MMapFile(const MMapFile &) = delete;
  MMapFile &operator=(const MMapFile &) = delete;

  MMapFile(MMapFile &&other) noexcept : data_(other.data_), size_(other.size_) {
    other.data_ = nullptr;
    other.size_ = 0;
  }

  MMapFile &operator=(MMapFile &&other) noexcept {
    if (this != &other) {
      if (data_)
        ::munmap(const_cast<uint8_t *>(data_), size_);

      data_ = other.data_;
      size_ = other.size_;

      other.data_ = nullptr;
      other.size_ = 0;
    }
    return *this;
  }

  const uint8_t *data() const { return data_; }
  size_t size() const { return size_; }
  bool valid() const { return data_ != nullptr; }

private:
  const uint8_t *data_ = nullptr;
  size_t size_ = 0;
};

boottype probe_type(MMapFile &bootimg);

// Detect the compression format of a section from its leading bytes. Returns
// the name used to recreate the section (e.g. "gzip"), or nullptr when the
// data is not compressed or the format is unsupported for re-compression.
const char *detect_format(const uint8_t *data, size_t size);

// Write `size` bytes to `path`, compressing them with `format` when it is not
// nullptr. `format` comes from detect_format() applied to the original
// section, so the rebuilt image keeps the section's original encoding.
bool compress_section(const char *path, const uint8_t *data, size_t size,
                      const char *format);

bool decompress_gzip(const char *filepath, const uint8_t *data, size_t size);
bool decompress_bzip2(const char *filepath, const uint8_t *data, size_t size);
bool decompress_lzop(const char *filepath, const uint8_t *data, size_t size);
bool decompress_lzma(const char *filepath, const uint8_t *data, size_t size);
bool decompress_lz4(const char *filepath, const uint8_t *data, size_t size);
bool decompress_lz4_legacy(const char *filepath, const uint8_t *data,
                           size_t size);
bool decompress_lz4_lg(const char *filepath, const uint8_t *data, size_t size);
bool decompress_xz(const char *filepath, const uint8_t *data, size_t size);

bool compress_gzip(const char *filepath, const uint8_t *data, size_t size);
bool compress_bzip2(const char *filepath, const uint8_t *data, size_t size);
bool compress_lzma(const char *filepath, const uint8_t *data, size_t size);
bool compress_xz(const char *filepath, const uint8_t *data, size_t size);
bool compress_lz4(const char *filepath, const uint8_t *data, size_t size);
bool compress_lz4_legacy(const char *filepath, const uint8_t *data, size_t size);
bool compress_lzop(const char *filepath, const uint8_t *data, size_t size);
} // namespace boot