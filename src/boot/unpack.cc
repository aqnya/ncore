#include "boot_internal.hpp"
#include "bootimg.h"
#include <fstream>
#include <iostream>
#include <string>

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

bool write_file(const char *path, const void *data, size_t size) {
  uint32_t magic;
  std::memcpy(&magic, data, sizeof(magic));
  switch (magic) {
  case GZIP2_MAGIC:
    std::cout << "gzip2 compress" << std::endl;
    break;
  case LZOP_MAGIC:
    std::cout << "lzo compress" << std::endl;
    break;
  case XZ_MAGIC:
    std::cout << "xz compress" << std::endl;
    break;
  case BZIP_MAGIC:
    std::cout << "bzip compress" << std::endl;
    break;
  case LZ41_MAGIC:
    std::cout << "lz41 compress" << std::endl;
    break;
  case LZ42_MAGIC:
    std::cout << "lz42 compress" << std::endl;
    break;
  case LZ4_LEG_MAGIC:
    std::cout << "lz4_leg compress" << std::endl;
    break;
  default: {
    if (size == 0)
      return true;
    std::ofstream out(path, std::ios::binary);
    if (!out)
      return false;

    out.write(static_cast<const char *>(data), size);
    std::cout << "write out " << path << std::endl;
    return out.good();
  }
  }
  return true;
}

template <typename H>
void dump_v1_common(const H &head, const MMapFile &image) {
  const size_t page = head.page_size;
  const auto *base = image.data();

  const size_t kernel_pages = (head.kernel_size + page - 1) / page;
  const size_t ramdisk_pages = (head.ramdisk_size + page - 1) / page;

  write_file("kernel", base + page, head.kernel_size);

  write_file("ramdisk", base + page + kernel_pages * page, head.ramdisk_size);

  write_file("second", base + page + (kernel_pages + ramdisk_pages) * page,
             head.second_size);
}

void dump_v1(const boot_img_hdr_v0 &head, const MMapFile &image) {
  dump_v1_common(head, image);
}

void dump_v1(const boot_img_hdr_v1 &head, const MMapFile &image) {
  dump_v1_common(head, image);

  write_file("recovery_dtbo", image.data() + head.recovery_dtbo_offset,
             head.recovery_dtbo_size);
}

void dump_v1(const boot_img_hdr_v2 &head, const MMapFile &image) {
  const size_t page = head.page_size;
  const size_t kernel_pages = (head.kernel_size + page - 1) / page;
  const size_t ramdisk_pages = (head.ramdisk_size + page - 1) / page;
  const auto *base = image.data();
  dump_v1_common(head, image);

  const size_t recovery_dtbo_page = (head.recovery_dtbo_size + page - 1) / page;

  write_file("recovery_dtbo", image.data() + head.recovery_dtbo_offset,
             head.recovery_dtbo_size);

  write_file("dtb",
             base + page +
                 (kernel_pages + ramdisk_pages + recovery_dtbo_page) * page,
             head.dtb_size);
}

template <typename H>
void dump_v2_common(const H &head, const MMapFile &image) {
  const size_t page = 4096;
  const auto *base = image.data();

  const size_t kernel_pages = (head.kernel_size + 4096 - 1) / 4096;

  write_file("kernel", base + page, head.kernel_size);

  write_file("ramdisk", base + page + kernel_pages * page, head.ramdisk_size);
}

void dump_v2(const boot_img_hdr_v3 &head, const MMapFile &image) {
  dump_v2_common(head, image);
}

template <typename T>
void dump_vendor_boot(const T &head, const MMapFile &image) {
  const auto *base = image.data();
  const size_t page = head.page_size;
  const size_t head_page = (2128 + page - 1) / page;
  const size_t vendor_ramdisk_page =
      (head.vendor_ramdisk_size + page - 1) / page;
  write_file("vendor_ramdisk", base + head_page * page,
             head.vendor_ramdisk_size);
  write_file("vendor_dtb", base + (head_page + vendor_ramdisk_page) * page,
             head.dtb_size);
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