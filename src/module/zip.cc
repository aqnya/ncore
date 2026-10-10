#include "zip.hpp"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <sys/stat.h>
#include <unistd.h>
#include <zlib.h>

namespace modules {

namespace {

constexpr uint32_t kLocalHeaderSig = 0x04034b50;
constexpr uint32_t kCentralHeaderSig = 0x02014b50;
constexpr uint32_t kEndOfCentralDirSig = 0x06054b50;
constexpr uint32_t kZip64EndOfCentralDirSig = 0x06064b50;
constexpr uint32_t kZip64EndOfCentralDirLocatorSig = 0x07064b50;

constexpr uint16_t kMethodStore = 0;
constexpr uint16_t kMethodDeflate = 8;
constexpr size_t kEndOfCentralDirSize = 22;

uint16_t read_u16(const uint8_t *p) {
  return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}

uint32_t read_u32(const uint8_t *p) {
  return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) |
         (static_cast<uint32_t>(p[3]) << 24);
}

uint64_t read_u64(const uint8_t *p) {
  return static_cast<uint64_t>(read_u32(p)) |
         (static_cast<uint64_t>(read_u32(p + 4)) << 32);
}

bool pread_all(int fd, uint64_t offset, void *buffer, size_t count) {
  uint8_t *out = static_cast<uint8_t *>(buffer);
  while (count > 0) {
    const ssize_t n = ::pread(fd, out, count, static_cast<off_t>(offset));
    if (n < 0) {
      if (errno == EINTR)
        continue;
      return false;
    }
    if (n == 0)
      return false; // unexpected EOF
    out += n;
    offset += static_cast<uint64_t>(n);
    count -= static_cast<size_t>(n);
  }
  return true;
}

void set_error(std::string *error, const std::string &message) {
  if (error != nullptr)
    *error = message;
}

// Split `name` into safe path components. Rejects absolute paths and `..`
// traversal so a malicious archive cannot escape the destination directory.
bool safe_components(const std::string &name, std::vector<std::string> &out) {
  if (name.empty() || name[0] == '/' || name[0] == '\\')
    return false;

  std::string component;
  for (char c : name) {
    if (c == '/' || c == '\\') {
      if (!component.empty()) {
        if (component == "..")
          return false;
        out.push_back(component);
        component.clear();
      }
    } else {
      component.push_back(c);
    }
  }
  if (component == "..")
    return false;
  if (!component.empty())
    out.push_back(component);
  return !out.empty();
}

} // namespace

ZipArchive::~ZipArchive() {
  if (fd_ >= 0)
    ::close(fd_);
}

bool ZipArchive::open(const std::string &path, std::string *error) {
  fd_ = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd_ < 0) {
    set_error(error, "cannot open " + path + ": " + std::strerror(errno));
    return false;
  }

  struct stat st {};
  if (::fstat(fd_, &st) != 0 || !S_ISREG(st.st_mode)) {
    set_error(error, path + " is not a regular file");
    return false;
  }
  size_ = static_cast<uint64_t>(st.st_size);
  if (size_ < kEndOfCentralDirSize) {
    set_error(error, "not a zip archive (too small)");
    return false;
  }

  // Locate the end of central directory record, scanning backwards through the
  // possible trailing comment.
  const size_t tail_size =
      static_cast<size_t>(size_ < kEndOfCentralDirSize + 0xFFFF
                              ? size_
                              : kEndOfCentralDirSize + 0xFFFF);
  std::vector<uint8_t> tail(tail_size);
  if (!pread_all(fd_, size_ - tail_size, tail.data(), tail_size)) {
    set_error(error, "failed to read central directory");
    return false;
  }

  size_t eocd = std::string::npos;
  for (size_t i = tail_size - kEndOfCentralDirSize + 1; i-- > 0;) {
    if (read_u32(&tail[i]) != kEndOfCentralDirSig)
      continue;
    // A comment may itself contain the signature; the real record is the one
    // whose comment length exactly reaches the end of the file.
    const uint16_t comment_len = read_u16(&tail[i + 20]);
    if (i + kEndOfCentralDirSize + comment_len == tail_size) {
      eocd = i;
      break;
    }
  }
  if (eocd == std::string::npos) {
    set_error(error, "end of central directory not found");
    return false;
  }

  uint64_t entry_count = read_u16(&tail[eocd + 10]);
  uint64_t cd_size = read_u32(&tail[eocd + 12]);
  uint64_t cd_offset = read_u32(&tail[eocd + 16]);

  // ZIP64: when any field is saturated the real values live in the ZIP64 end of
  // central directory record, pointed at by the locator just before the EOCD.
  if (eocd >= 20 &&
      read_u32(&tail[eocd - 20]) == kZip64EndOfCentralDirLocatorSig) {
    const uint64_t zip64_offset = read_u64(&tail[eocd - 20 + 8]);
    uint8_t header[56];
    if (!pread_all(fd_, zip64_offset, header, sizeof(header)) ||
        read_u32(header) != kZip64EndOfCentralDirSig) {
      set_error(error, "invalid zip64 end of central directory");
      return false;
    }
    entry_count = read_u64(header + 32);
    cd_size = read_u64(header + 40);
    cd_offset = read_u64(header + 48);
  }

  if (cd_offset + cd_size > size_) {
    set_error(error, "central directory is out of bounds");
    return false;
  }
  if (entry_count > (1u << 20)) {
    set_error(error, "archive has too many entries");
    return false;
  }

  std::vector<uint8_t> central(static_cast<size_t>(cd_size));
  if (cd_size > 0 && !pread_all(fd_, cd_offset, central.data(), central.size())) {
    set_error(error, "failed to read central directory");
    return false;
  }

  size_t pos = 0;
  for (uint64_t i = 0; i < entry_count; ++i) {
    if (pos + 46 > central.size() ||
        read_u32(&central[pos]) != kCentralHeaderSig) {
      set_error(error, "corrupt central directory entry");
      return false;
    }

    const uint8_t *h = &central[pos];
    const uint16_t version_made_by = read_u16(h + 4);
    const uint16_t flags = read_u16(h + 8);
    const uint16_t method = read_u16(h + 10);
    const uint32_t crc = read_u32(h + 16);
    uint64_t compressed = read_u32(h + 20);
    uint64_t uncompressed = read_u32(h + 24);
    const uint16_t name_len = read_u16(h + 28);
    const uint16_t extra_len = read_u16(h + 30);
    const uint16_t comment_len = read_u16(h + 32);
    const uint32_t external_attrs = read_u32(h + 38);
    uint64_t local_offset = read_u32(h + 42);

    if (pos + 46 + name_len + extra_len + comment_len > central.size()) {
      set_error(error, "truncated central directory entry");
      return false;
    }

    // The ZIP64 extra field carries the real values for any saturated 32-bit
    // field, in this fixed order.
    if (uncompressed == 0xFFFFFFFFu || compressed == 0xFFFFFFFFu ||
        local_offset == 0xFFFFFFFFu) {
      const uint8_t *extra = h + 46 + name_len;
      size_t remaining = extra_len;
      while (remaining >= 4) {
        const uint16_t id = read_u16(extra);
        const uint16_t len = read_u16(extra + 2);
        if (remaining < 4 + len)
          break;
        if (id == 0x0001) {
          const uint8_t *z = extra + 4;
          if (uncompressed == 0xFFFFFFFFu) {
            uncompressed = read_u64(z);
            z += 8;
          }
          if (compressed == 0xFFFFFFFFu) {
            compressed = read_u64(z);
            z += 8;
          }
          if (local_offset == 0xFFFFFFFFu)
            local_offset = read_u64(z);
          break;
        }
        extra += 4 + len;
        remaining -= 4 + len;
      }
    }

    if (flags & 0x0001) {
      set_error(error, "encrypted zip entries are not supported");
      return false;
    }

    Entry entry;
    entry.name.assign(reinterpret_cast<const char *>(h + 46), name_len);
    entry.method = method;
    entry.crc32 = crc;
    entry.compressed_size = compressed;
    entry.uncompressed_size = uncompressed;
    entry.local_header_offset = local_offset;

    // Only trust the external attributes when the archive was made on unix.
    if ((version_made_by >> 8) == 3)
      entry.mode = external_attrs >> 16;

    entry.is_dir = (!entry.name.empty() && entry.name.back() == '/') ||
                   (entry.mode != 0 && S_ISDIR(entry.mode));
    entry.is_symlink = entry.mode != 0 && S_ISLNK(entry.mode);

    entries_.push_back(std::move(entry));
    pos += 46 + name_len + extra_len + comment_len;
  }

  return true;
}

uint64_t ZipArchive::uncompressed_size() const {
  uint64_t total = 0;
  for (const Entry &entry : entries_)
    total += entry.uncompressed_size;
  return total;
}

bool ZipArchive::read_entry(const Entry &entry, std::string &out,
                            std::string *error) const {
  uint8_t header[30];
  if (!pread_all(fd_, entry.local_header_offset, header, sizeof(header)) ||
      read_u32(header) != kLocalHeaderSig) {
    set_error(error, "invalid local header for " + entry.name);
    return false;
  }

  const uint16_t name_len = read_u16(header + 26);
  const uint16_t extra_len = read_u16(header + 28);
  const uint64_t data_offset =
      entry.local_header_offset + 30 + name_len + extra_len;

  if (data_offset + entry.compressed_size > size_) {
    set_error(error, "entry data is out of bounds: " + entry.name);
    return false;
  }

  std::string compressed(static_cast<size_t>(entry.compressed_size), '\0');
  if (entry.compressed_size > 0 &&
      !pread_all(fd_, data_offset, &compressed[0], compressed.size())) {
    set_error(error, "failed to read entry: " + entry.name);
    return false;
  }

  if (entry.method == kMethodStore) {
    out = std::move(compressed);
  } else if (entry.method == kMethodDeflate) {
    out.assign(static_cast<size_t>(entry.uncompressed_size), '\0');

    // zlib needs a non-null output buffer even for a zero-length stream, so
    // point it at a scratch byte when the entry expands to nothing.
    Bytef scratch = 0;
    z_stream strm{};
    strm.next_in = reinterpret_cast<Bytef *>(compressed.data());
    strm.avail_in = static_cast<uInt>(compressed.size());
    strm.next_out = out.empty() ? &scratch
                                : reinterpret_cast<Bytef *>(&out[0]);
    strm.avail_out = static_cast<uInt>(out.empty() ? 1 : out.size());

    if (inflateInit2(&strm, -15) != Z_OK) {
      set_error(error, "inflateInit2 failed for " + entry.name);
      return false;
    }
    const int ret = inflate(&strm, Z_FINISH);
    inflateEnd(&strm);
    if (ret != Z_STREAM_END) {
      set_error(error, "failed to inflate " + entry.name);
      return false;
    }
    out.resize(strm.total_out);
  } else {
    set_error(error, "unsupported compression method for " + entry.name);
    return false;
  }

  const uint32_t actual = crc32(
      0, reinterpret_cast<const Bytef *>(out.empty() ? "" : out.data()),
      static_cast<uInt>(out.size()));
  if (actual != entry.crc32) {
    set_error(error, "crc mismatch for " + entry.name);
    return false;
  }
  return true;
}

bool ZipArchive::read(const std::string &name, std::string &out,
                      std::string *error) const {
  for (const Entry &entry : entries_) {
    if (entry.name == name && !entry.is_dir)
      return read_entry(entry, out, error);
  }
  set_error(error, name + " not found in archive");
  return false;
}

bool ZipArchive::extract_all(const std::string &dest_dir,
                             std::string *error) const {
  for (const Entry &entry : entries_) {
    std::vector<std::string> parts;
    if (!safe_components(entry.name, parts)) {
      set_error(error, "unsafe path in archive: " + entry.name);
      return false;
    }

    std::string path = dest_dir;
    for (size_t i = 0; i < parts.size(); ++i) {
      path += "/";
      path += parts[i];
    }

    const uint32_t mode = entry.mode & 07777;

    if (entry.is_dir) {
      if (::mkdir(path.c_str(), 0755) != 0 && errno != EEXIST) {
        set_error(error, "mkdir failed: " + path + ": " + std::strerror(errno));
        return false;
      }
      if (mode != 0)
        ::chmod(path.c_str(), mode | 0700);
      continue;
    }

    // Make sure the parent chain exists (archives may omit directory entries).
    std::string parent = path.substr(0, path.find_last_of('/'));
    for (size_t i = 1; i <= parent.size(); ++i) {
      if (i == parent.size() || parent[i] == '/') {
        ::mkdir(parent.substr(0, i).c_str(), 0755);
      }
    }

    std::string content;
    if (!read_entry(entry, content, error))
      return false;

    ::unlink(path.c_str());
    if (entry.is_symlink) {
      if (::symlink(content.c_str(), path.c_str()) != 0) {
        set_error(error,
                  "symlink failed: " + path + ": " + std::strerror(errno));
        return false;
      }
      continue;
    }

    const int fd = ::open(path.c_str(),
                          O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
      set_error(error, "open failed: " + path + ": " + std::strerror(errno));
      return false;
    }
    size_t written = 0;
    bool ok = true;
    while (written < content.size()) {
      const ssize_t n =
          ::write(fd, content.data() + written, content.size() - written);
      if (n < 0) {
        if (errno == EINTR)
          continue;
        ok = false;
        break;
      }
      written += static_cast<size_t>(n);
    }
    ::close(fd);
    if (!ok) {
      set_error(error, "write failed: " + path + ": " + std::strerror(errno));
      return false;
    }

    if (mode != 0)
      ::chmod(path.c_str(), mode);
    else
      ::chmod(path.c_str(), 0644);
  }
  return true;
}

} // namespace modules
