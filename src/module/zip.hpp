#pragma once

#include <cstdint>
#include <string>
#include <vector>

// Minimal read-only ZIP reader used by the module installer. KernelSU reads
// module packages with the Rust `zip` crate; ncore does not link a zip library,
// so this implements just enough of the format for module installation: stored
// (0), deflate (8) and xz (95) entries, enumerated through the central
// directory.
namespace modules {

class ZipArchive {
public:
  struct Entry {
    std::string name;
    uint16_t method = 0;
    uint32_t crc32 = 0;
    uint64_t compressed_size = 0;
    uint64_t uncompressed_size = 0;
    // Unix mode bits taken from the central directory's external attributes,
    // or 0 when the archive was produced on a non-unix host.
    uint32_t mode = 0;
    uint64_t local_header_offset = 0;
    bool is_dir = false;
    bool is_symlink = false;
  };

  ZipArchive() = default;
  ~ZipArchive();

  ZipArchive(const ZipArchive &) = delete;
  ZipArchive &operator=(const ZipArchive &) = delete;

  // Open and index the archive. On failure returns false and, when non-null,
  // fills `error` with a human readable reason.
  bool open(const std::string &path, std::string *error = nullptr);

  const std::vector<Entry> &entries() const { return entries_; }

  // Sum of the uncompressed sizes of every entry.
  uint64_t uncompressed_size() const;

  // Read one entry (matched by exact name) into `out`.
  bool read(const std::string &name, std::string &out,
            std::string *error = nullptr) const;

  // Extract every entry below `dest_dir`, recreating directories and symlinks.
  bool extract_all(const std::string &dest_dir,
                   std::string *error = nullptr) const;

private:
  bool read_entry(const Entry &entry, std::string &out,
                  std::string *error) const;

  int fd_ = -1;
  uint64_t size_ = 0;
  std::vector<Entry> entries_;
};

} // namespace modules
