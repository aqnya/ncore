#include "boot_internal.hpp"
#include "bootimg.h"
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace boot {
namespace {

MMapFile load(const char *filepath) { return MMapFile(filepath); }

template <typename T>
bool read_struct(const MMapFile &image, size_t offset, T &out) {
  if (offset > image.size() || sizeof(T) > image.size() - offset)
    return false;

  std::memcpy(&out, image.data() + offset, sizeof(T));
  return true;
}

// Detect an lzma-alone (.lzma / LZMA1) stream, which has no reliable magic
// number. The header encodes the lc/lp/pb byte, a power-of-two dictionary
// size and eight 0xff bytes (unknown uncompressed size).
bool is_lzma_alone(const uint8_t *data, size_t size) {
  if (size < 13 || data[0] != 0x5d)
    return false;

  uint32_t dict = static_cast<uint32_t>(data[1]) |
                  (static_cast<uint32_t>(data[2]) << 8) |
                  (static_cast<uint32_t>(data[3]) << 16) |
                  (static_cast<uint32_t>(data[4]) << 24);
  if (dict == 0 || (dict & (dict - 1)) != 0)
    return false;

  for (size_t i = 5; i < 13; ++i) {
    if (data[i] != 0xff)
      return false;
  }
  return true;
}

template <typename T>
T read_le(const uint8_t *data, size_t size) {
  T value = 0;
  std::memcpy(&value, data, sizeof(T) < size ? sizeof(T) : size);
  return value;
}

bool write_file(const char *path, const void *data, size_t size) {
  if (size == 0)
    return true;

  std::cout << "write out " << path << std::endl;

  const uint8_t *bytes = static_cast<const uint8_t *>(data);

  if (size >= 2) {
    const uint16_t magic16 = read_le<uint16_t>(bytes, size);
    if (magic16 == GZIP1_MAGIC) {
      std::cout << "gzip compress" << std::endl;
      return decompress_gzip(path, bytes, size);
    }
    if (magic16 == GZIP2_MAGIC) {
      std::cout << "gzip2 compress" << std::endl;
      return decompress_gzip(path, bytes, size);
    }
  }

  // "BZh" must be followed by a compression level digit.
  if (size >= 4 && (read_le<uint32_t>(bytes, size) & 0x00ffffff) == BZIP_MAGIC &&
      bytes[3] >= '1' && bytes[3] <= '9') {
    std::cout << "bzip2 compress" << std::endl;
    return decompress_bzip2(path, bytes, size);
  }

  if (size >= 4) {
    switch (read_le<uint32_t>(bytes, size)) {
    case LZOP_MAGIC:
      std::cout << "lzo compress" << std::endl;
      return decompress_lzop(path, bytes, size);
    case XZ_MAGIC:
      std::cout << "xz compress" << std::endl;
      return decompress_xz(path, bytes, size);
    case LZ41_MAGIC:
      std::cout << "lz4_lg compress" << std::endl;
      return decompress_lz4_lg(path, bytes, size);
    case LZ42_MAGIC:
      std::cout << "lz42 compress" << std::endl;
      return decompress_lz4(path, bytes, size);
    case LZ4_LEG_MAGIC:
      std::cout << "lz4_leg compress" << std::endl;
      return decompress_lz4_legacy(path, bytes, size);
    default:
      break;
    }
  }

  if (is_lzma_alone(bytes, size)) {
    std::cout << "lzma compress" << std::endl;
    return decompress_lzma(path, bytes, size);
  }

  // Unknown/raw section: dump as-is.
  std::ofstream out(path, std::ios::binary);
  if (!out)
    return false;

  out.write(static_cast<const char *>(data), size);
  return out.good();
}

// Bounds-check a section described by (offset, size) against the mapped image
// and dump it to `path`. Empty sections are ignored.
bool write_section(const char *path, const MMapFile &image, size_t offset,
                   size_t size) {
  if (size == 0)
    return true;

  if (offset > image.size() || size > image.size() - offset) {
    std::cerr << path << ": section out of bounds (offset " << offset
              << ", size " << size << ", image " << image.size() << ")\n";
    return false;
  }

  return write_file(path, image.data() + offset, size);
}

template <typename H>
void dump_v1_common(const H &head, const MMapFile &image) {
  const size_t page = head.page_size;

  const size_t kernel_pages = (head.kernel_size + page - 1) / page;
  const size_t ramdisk_pages = (head.ramdisk_size + page - 1) / page;

  write_section("kernel", image, page, head.kernel_size);

  write_section("ramdisk", image, page + kernel_pages * page,
                head.ramdisk_size);

  write_section("second", image, page + (kernel_pages + ramdisk_pages) * page,
                head.second_size);
}

void dump_v1(const boot_img_hdr_v0 &head, const MMapFile &image) {
  dump_v1_common(head, image);
}

void dump_v1(const boot_img_hdr_v1 &head, const MMapFile &image) {
  dump_v1_common(head, image);

  write_section("recovery_dtbo", image, head.recovery_dtbo_offset,
                head.recovery_dtbo_size);
}

void dump_v1(const boot_img_hdr_v2 &head, const MMapFile &image) {
  const size_t page = head.page_size;
  const size_t kernel_pages = (head.kernel_size + page - 1) / page;
  const size_t ramdisk_pages = (head.ramdisk_size + page - 1) / page;
  const size_t second_pages = (head.second_size + page - 1) / page;
  dump_v1_common(head, image);

  const size_t recovery_dtbo_page = (head.recovery_dtbo_size + page - 1) / page;

  write_section("recovery_dtbo", image, head.recovery_dtbo_offset,
                head.recovery_dtbo_size);

  write_section(
      "dtb", image,
      page + (kernel_pages + ramdisk_pages + second_pages + recovery_dtbo_page) *
                 page,
      head.dtb_size);
}

template <typename H>
void dump_v2_common(const H &head, const MMapFile &image) {
  const size_t page = 4096;

  const size_t kernel_pages = (head.kernel_size + page - 1) / page;

  write_section("kernel", image, page, head.kernel_size);

  write_section("ramdisk", image, page + kernel_pages * page,
                head.ramdisk_size);
}

void dump_v2(const boot_img_hdr_v3 &head, const MMapFile &image) {
  dump_v2_common(head, image);
}

void dump_v2(const boot_img_hdr_v4 &head, const MMapFile &image) {
  dump_v2_common(head, image);

  const size_t page = 4096;
  const size_t kernel_pages = (head.kernel_size + page - 1) / page;
  const size_t ramdisk_pages = (head.ramdisk_size + page - 1) / page;

  write_section("boot_signature", image,
                page + (kernel_pages + ramdisk_pages) * page,
                head.signature_size);
}

template <typename T>
void dump_vendor_boot_v3(const T &head, const MMapFile &image) {
  const size_t page = head.page_size;
  const size_t head_page = (2128 + page - 1) / page;
  const size_t vendor_ramdisk_page =
      (head.vendor_ramdisk_size + page - 1) / page;
  write_section("vendor_ramdisk", image, head_page * page,
                head.vendor_ramdisk_size);
  write_section("vendor_dtb", image,
                (head_page + vendor_ramdisk_page) * page, head.dtb_size);
}

void dump_vendor_boot(const vendor_boot_img_hdr_v3 &head,
                      const MMapFile &image) {
  dump_vendor_boot_v3(head, image);
}

void dump_vendor_boot(const vendor_boot_img_hdr_v4 &head,
                      const MMapFile &image) {
  const size_t page = head.page_size;
  const size_t head_page = (2128 + page - 1) / page;
  const size_t vendor_ramdisk_page =
      (head.vendor_ramdisk_size + page - 1) / page;
  const size_t dtb_page = (head.dtb_size + page - 1) / page;
  const size_t table_page =
      (head.vendor_ramdisk_table_size + page - 1) / page;

  const size_t vendor_ramdisk_offset = head_page * page;
  const size_t dtb_offset = vendor_ramdisk_offset + vendor_ramdisk_page * page;
  const size_t table_offset = dtb_offset + dtb_page * page;
  const size_t bootconfig_offset = table_offset + table_page * page;

  write_section("vendor_ramdisk", image, vendor_ramdisk_offset,
                head.vendor_ramdisk_size);
  write_section("vendor_dtb", image, dtb_offset, head.dtb_size);
  write_section("vendor_ramdisk_table", image, table_offset,
                head.vendor_ramdisk_table_size);
  write_section("bootconfig", image, bootconfig_offset, head.bootconfig_size);

  // Split the vendor ramdisk section into the individual ramdisks described
  // by the ramdisk table.
  if (head.vendor_ramdisk_table_entry_size !=
      sizeof(vendor_ramdisk_table_entry_v4)) {
    std::cerr << "vendor_ramdisk_table: unexpected entry size "
              << head.vendor_ramdisk_table_entry_size << "\n";
    return;
  }

  for (uint32_t i = 0; i < head.vendor_ramdisk_table_entry_num; ++i) {
    vendor_ramdisk_table_entry_v4 entry;
    if (!read_struct(image,
                     table_offset +
                         static_cast<size_t>(i) *
                             head.vendor_ramdisk_table_entry_size,
                     entry)) {
      std::cerr << "vendor_ramdisk_table: truncated entry " << i << "\n";
      return;
    }

    if (entry.ramdisk_size == 0)
      continue;

    if (entry.ramdisk_offset > head.vendor_ramdisk_size ||
        entry.ramdisk_size >
            head.vendor_ramdisk_size - entry.ramdisk_offset) {
      std::cerr << "vendor_ramdisk_table: entry " << i << " out of bounds\n";
      continue;
    }

    std::string name = "vendor_ramdisk.";
    const size_t name_len =
        strnlen(reinterpret_cast<const char *>(entry.ramdisk_name),
                sizeof(entry.ramdisk_name));
    if (name_len != 0)
      name.append(reinterpret_cast<const char *>(entry.ramdisk_name),
                  name_len);
    else
      name += std::to_string(i);

    write_section(name.c_str(), image,
                  vendor_ramdisk_offset + entry.ramdisk_offset,
                  entry.ramdisk_size);
  }
}
} // namespace
int unpack(const std::string filepath) {
  auto image = load(filepath.c_str());
  if (!image.valid())
    return -1;
  std::cout << "unpacking " << filepath << std::endl;
  boottype b = probe_type(image);
  switch (b) {
  case boottype::boot_img_hdr_v0: {
    boot_img_hdr_v0 head;
    if (!read_struct(image, 0, head))
      return -1;
    dump_v1(head, image);
    break;
  }
  case boottype::boot_img_hdr_v1: {
    boot_img_hdr_v1 head;
    if (!read_struct(image, 0, head))
      return -1;
    dump_v1(head, image);
    break;
  }
  case boottype::boot_img_hdr_v2: {
    boot_img_hdr_v2 head;
    if (!read_struct(image, 0, head))
      return -1;
    dump_v1(head, image);
    break;
  }
  case boottype::boot_img_hdr_v3: {
    boot_img_hdr_v3 head;
    if (!read_struct(image, 0, head))
      return -1;
    dump_v2(head, image);
    break;
  }
  case boottype::boot_img_hdr_v4: {
    boot_img_hdr_v4 head;
    if (!read_struct(image, 0, head))
      return -1;
    dump_v2(head, image);
    break;
  }
  case boottype::vendor_boot_img_hdr_v3: {
    vendor_boot_img_hdr_v3 head;
    if (!read_struct(image, 0, head))
      return -1;
    dump_vendor_boot(head, image);
    break;
  }
  case boottype::vendor_boot_img_hdr_v4: {
    vendor_boot_img_hdr_v4 head;
    if (!read_struct(image, 0, head))
      return -1;
    dump_vendor_boot(head, image);
    break;
  }
  case boottype::invalid:
    std::cout << "invalid boot!" << std::endl;
    return -1;
  }
  return 0;
}
} // namespace boot