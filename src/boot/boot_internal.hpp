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

constexpr uint32_t GZIP2_MAGIC   = 0x00009e1f;
constexpr uint32_t LZOP_MAGIC    = 0x4f5a4c89;
constexpr uint32_t XZ_MAGIC      = 0x587a37fd;
constexpr uint32_t LZ41_MAGIC    = 0x184c2103;
constexpr uint32_t LZ42_MAGIC    = 0x184d2204;
constexpr uint32_t LZ4_LEG_MAGIC = 0x184c2102;

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
void decompress_lz4(const char* filepath,const uint8_t *data, size_t size);
bool decompress_lz4_legacy(const char* filepath,const uint8_t *data, size_t size);
bool decompress_xz(const char *filepath, const uint8_t *data, size_t size);
} // namespace boot