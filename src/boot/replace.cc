#include "boot_internal.hpp"
#include "bootimg.h"
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace boot {
namespace {

template <typename T>
bool read_struct(const MMapFile &image, size_t offset, T &out) {
  if (offset > image.size() || sizeof(T) > image.size() - offset)
    return false;

  std::memcpy(&out, image.data() + offset, sizeof(T));
  return true;
}

template <typename T>
T read_le(const uint8_t *data, size_t size) {
  T value = 0;
  std::memcpy(&value, data, sizeof(T) < size ? sizeof(T) : size);
  return value;
}

template <typename T>
void write_le(std::vector<uint8_t> &buf, size_t offset, T value) {
  std::memcpy(buf.data() + offset, &value, sizeof(T));
}

size_t align_up(size_t value, size_t page) {
  return (value + page - 1) / page * page;
}

// One section of a boot image, in the order it appears on disk. `data` points
// into a backing store owned by the caller.
struct section {
  std::string name;
  const uint8_t *data = nullptr;
  size_t size = 0;
  // Offset of the u32 size field inside the boot header, or `npos` when the
  // section has no size field (e.g. v3/v4 kernel/ramdisk are addressed
  // implicitly by order, only their sizes are stored).
  size_t size_field = std::string::npos;
  // Offset of a u64 offset field inside the header, if the format uses one.
  size_t offset_field = std::string::npos;
};

constexpr size_t npos = std::string::npos;

// On-disk field offsets inside the boot header.
//
// These cannot be obtained with `offsetof` for the versioned headers: v1/v2/v4
// (and vendor v4) are derived from their predecessors, which makes them
// non-standard-layout types, and `offsetof` on such a type is undefined
// behaviour (-Winvalid-offsetof). The values are therefore spelled out here and
// kept in sync with the AOSP struct definitions in bootimg.h. Each one is the
// offset of the field from the start of the boot image (the header begins at
// offset 0), so they are independent of the struct sizes.
constexpr size_t V0_KERNEL_SIZE_OFF = 8;
constexpr size_t V0_RAMDISK_SIZE_OFF = 16;
constexpr size_t V0_SECOND_SIZE_OFF = 24;
// v1 appends recovery_dtbo_size (u32) + recovery_dtbo_offset (u64) + header_size
// after the 1632-byte v0 base.
constexpr size_t V1_RECOVERY_DTBO_SIZE_OFF = 1632;
constexpr size_t V1_RECOVERY_DTBO_OFFSET_OFF = 1636;
// v2 appends dtb_size (u32) + dtb_addr (u64) after the 1648-byte v1 base.
constexpr size_t V2_DTB_SIZE_OFF = 1648;
// v3 boot header field offsets.
constexpr size_t V3_KERNEL_SIZE_OFF = 8;
constexpr size_t V3_RAMDISK_SIZE_OFF = 12;
// v4 appends signature_size (u32) after the 1580-byte v3 base.
constexpr size_t V4_SIGNATURE_SIZE_OFF = 1580;
// vendor v3 header field offsets.
constexpr size_t VENDOR_V3_RAMDISK_SIZE_OFF = 24;
constexpr size_t VENDOR_V3_DTB_SIZE_OFF = 2100;
// vendor v4 appends the table fields after the 2112-byte vendor v3 base.
constexpr size_t VENDOR_V4_TABLE_SIZE_OFF = 2112;
constexpr size_t VENDOR_V4_TABLE_ENTRY_NUM_OFF = 2116;
constexpr size_t VENDOR_V4_BOOTCONFIG_SIZE_OFF = 2124;

// Tie the offsets above to the actual struct layout so a change to bootimg.h
// cannot silently desynchronise them. sizeof is well-defined even for the
// non-standard-layout derived headers, unlike offsetof.
static_assert(sizeof(boot_img_hdr_v0) == 1632,
              "boot_img_hdr_v0 layout changed; update the V0_* offsets");
static_assert(sizeof(boot_img_hdr_v1) == 1648,
              "boot_img_hdr_v1 layout changed; update the V1_* offsets");
static_assert(sizeof(boot_img_hdr_v2) == 1660,
              "boot_img_hdr_v2 layout changed; update the V2_* offsets");
static_assert(sizeof(boot_img_hdr_v3) == 1580,
              "boot_img_hdr_v3 layout changed; update the V3_* offsets");
static_assert(sizeof(boot_img_hdr_v4) == 1584,
              "boot_img_hdr_v4 layout changed; update the V4_* offsets");
static_assert(sizeof(vendor_boot_img_hdr_v3) == 2112,
              "vendor_boot_img_hdr_v3 layout changed; update the VENDOR_V3_* "
              "offsets");
static_assert(sizeof(vendor_boot_img_hdr_v4) == 2128,
              "vendor_boot_img_hdr_v4 layout changed; update the VENDOR_V4_* "
              "offsets");

} // namespace

// Rebuild `original` with the section picked by the replacement file name
// swapped for the (recompressed) contents of `new_file`. Every section is
// re-laid-out page aligned and all size/offset fields in the header are
// updated, so the result stays a well-formed boot image even when the
// replacement changes size.
int replace(const std::string original, const std::string new_file) {
  MMapFile image(original.c_str());
  if (!image.valid()) {
    std::cerr << "replace: cannot open " << original << std::endl;
    return -1;
  }

  MMapFile new_raw(new_file.c_str());
  if (!new_raw.valid()) {
    std::cerr << "replace: cannot open " << new_file << std::endl;
    return -1;
  }

  const boottype b = probe_type(image);
  if (b == boottype::invalid) {
    std::cout << "invalid boot!" << std::endl;
    return -1;
  }

  // Match the new file name against a known section. `dtb` maps to the DTB,
  // anything else replaces the kernel.
  std::string name = new_file;
  const size_t slash = name.find_last_of('/');
  if (slash != std::string::npos)
    name = name.substr(slash + 1);
  const bool want_dtb = name.find("dtb") != std::string::npos;
  // Vendor boot images have no kernel: the primary replaceable section is the
  // vendor ramdisk. Everything that is not the dtb maps to it there.
  const bool is_vendor =
      b == boottype::vendor_boot_img_hdr_v3 ||
      b == boottype::vendor_boot_img_hdr_v4;

  std::vector<section> sections;
  size_t page = 4096;
  size_t header_size = 0;

  // Collect the ordered sections and their header field offsets per format.
  switch (b) {
  case boottype::boot_img_hdr_v0:
  case boottype::boot_img_hdr_v1:
  case boottype::boot_img_hdr_v2: {
    boot_img_hdr_v2 head{};
    if (!read_struct(image, 0, head)) {
      std::cerr << "replace: truncated header" << std::endl;
      return -1;
    }
    page = head.page_size;
    if (page == 0) {
      std::cerr << "replace: invalid page size" << std::endl;
      return -1;
    }

    if (b == boottype::boot_img_hdr_v2)
      header_size = sizeof(boot_img_hdr_v2);
    else if (b == boottype::boot_img_hdr_v1)
      header_size = sizeof(boot_img_hdr_v1);
    else
      header_size = sizeof(boot_img_hdr_v0);

    const size_t ksize = V0_KERNEL_SIZE_OFF;
    const size_t rsize = V0_RAMDISK_SIZE_OFF;
    const size_t ssize = V0_SECOND_SIZE_OFF;

    sections.push_back({"kernel", image.data() + page, head.kernel_size, ksize});
    sections.push_back({"ramdisk",
                        image.data() + page + align_up(head.kernel_size, page),
                        head.ramdisk_size, rsize});
    sections.push_back({"second",
                        image.data() + page + align_up(head.kernel_size, page) +
                            align_up(head.ramdisk_size, page),
                        head.second_size, ssize});

    if (b == boottype::boot_img_hdr_v1 || b == boottype::boot_img_hdr_v2) {
      const boot_img_hdr_v1 &h1 = head;
      const size_t roff = V1_RECOVERY_DTBO_OFFSET_OFF;
      const size_t rsz = V1_RECOVERY_DTBO_SIZE_OFF;
      sections.push_back({"recovery_dtbo",
                          image.data() + h1.recovery_dtbo_offset,
                          h1.recovery_dtbo_size, rsz, roff});
    }

    if (b == boottype::boot_img_hdr_v2) {
      const boot_img_hdr_v2 &h2 = head;
      const size_t dsize = V2_DTB_SIZE_OFF;
      sections.push_back({"dtb",
                          image.data() +
                              page + align_up(head.kernel_size, page) +
                              align_up(head.ramdisk_size, page) +
                              align_up(head.second_size, page) +
                              align_up(h2.recovery_dtbo_size, page),
                          h2.dtb_size, dsize});
    }
    break;
  }
  case boottype::boot_img_hdr_v3:
  case boottype::boot_img_hdr_v4: {
    page = 4096;
    size_t kernel_size = 0, ramdisk_size = 0, signature_size = 0;
    if (b == boottype::boot_img_hdr_v4) {
      boot_img_hdr_v4 head{};
      if (!read_struct(image, 0, head))
        return -1;
      kernel_size = head.kernel_size;
      ramdisk_size = head.ramdisk_size;
      signature_size = head.signature_size;
    } else {
      boot_img_hdr_v3 head{};
      if (!read_struct(image, 0, head))
        return -1;
      kernel_size = head.kernel_size;
      ramdisk_size = head.ramdisk_size;
    }

    const size_t ksize = V3_KERNEL_SIZE_OFF;
    const size_t rsize = V3_RAMDISK_SIZE_OFF;
    sections.push_back({"kernel", image.data() + page, kernel_size, ksize});
    sections.push_back({"ramdisk", image.data() + page + align_up(kernel_size, page),
                        ramdisk_size, rsize});
    if (b == boottype::boot_img_hdr_v4) {
      const size_t sigsize = V4_SIGNATURE_SIZE_OFF;
      sections.push_back({"boot_signature",
                          image.data() + page + align_up(kernel_size, page) +
                              align_up(ramdisk_size, page),
                          signature_size, sigsize});
    }
    header_size = b == boottype::boot_img_hdr_v4 ? sizeof(boot_img_hdr_v4)
                                                 : sizeof(boot_img_hdr_v3);
    break;
  }
  case boottype::vendor_boot_img_hdr_v3:
  case boottype::vendor_boot_img_hdr_v4: {
    vendor_boot_img_hdr_v4 head{};
    if (!read_struct(image, 0, head)) {
      std::cerr << "replace: truncated vendor header" << std::endl;
      return -1;
    }
    page = head.page_size;
    if (page == 0) {
      std::cerr << "replace: invalid page size" << std::endl;
      return -1;
    }
    header_size = 2128;
    const size_t vrsize = VENDOR_V3_RAMDISK_SIZE_OFF;
    const size_t dsize = VENDOR_V3_DTB_SIZE_OFF;

    const size_t vramdisk_off = align_up(header_size, page);
    sections.push_back({"vendor_ramdisk", image.data() + vramdisk_off,
                        head.vendor_ramdisk_size, vrsize});
    const size_t dtb_off = vramdisk_off + align_up(head.vendor_ramdisk_size, page);
    sections.push_back({"vendor_dtb", image.data() + dtb_off, head.dtb_size,
                        dsize});

    if (b == boottype::vendor_boot_img_hdr_v4) {
      const size_t toff = dtb_off + align_up(head.dtb_size, page);
      const size_t tsize = VENDOR_V4_TABLE_SIZE_OFF;
      sections.push_back({"vendor_ramdisk_table", image.data() + toff,
                          head.vendor_ramdisk_table_size, tsize});

      const size_t boff = toff + align_up(head.vendor_ramdisk_table_size, page);
      const size_t bsize = VENDOR_V4_BOOTCONFIG_SIZE_OFF;
      sections.push_back({"bootconfig", image.data() + boff,
                          head.bootconfig_size, bsize});
    }
    break;
  }
  case boottype::invalid:
    return -1;
  }

  if (page == 0 || header_size == 0) {
    std::cerr << "replace: unsupported boot image layout" << std::endl;
    return -1;
  }

  // Validate the original sections against the mapped image before touching
  // anything.
  for (const section &s : sections) {
    if (s.size == 0)
      continue;
    if (s.data < image.data() ||
        static_cast<size_t>(s.data - image.data()) + s.size > image.size()) {
      std::cerr << "replace: section " << s.name << " out of bounds"
                << std::endl;
      return -1;
    }
  }

  // Find the section to swap in. Original sections point into `image`.
  section *target = nullptr;
  for (section &s : sections) {
    bool matches;
    if (want_dtb)
      matches = (s.name == "dtb" || s.name == "vendor_dtb");
    else if (is_vendor)
      matches = (s.name == "vendor_ramdisk");
    else
      matches = (s.name == "kernel");

    if (matches) {
      target = &s;
      break;
    }
  }

  if (target == nullptr) {
    std::cerr << "replace: no matching section for " << new_file << std::endl;
    return -1;
  }

  // Compress the replacement to match the encoding of the section it replaces.
  const char *format = target->size == 0
                           ? nullptr
                           : detect_format(target->data, target->size);
  const std::string tmp_name = original + ".section";
  if (!compress_section(tmp_name.c_str(), new_raw.data(), new_raw.size(),
                        format)) {
    std::cerr << "replace: failed to compress " << new_file << std::endl;
    return -1;
  }

  MMapFile replacement(tmp_name.c_str());
  if (!replacement.valid()) {
    std::cerr << "replace: failed to read compressed section" << std::endl;
    std::remove(tmp_name.c_str());
    return -1;
  }

  const std::string replaced_name = target->name;
  target->data = replacement.data();
  target->size = replacement.size();

  // A v4 vendor ramdisk section is a concatenation of one or more individually
  // compressed ramdisks, and every vendor_ramdisk_table entry describes one of
  // those sub-ranges. Since the replacement swaps the whole section for a single
  // image, the table no longer matches: rewrite it as one entry spanning the new
  // section. For the common single-entry table this is just an in-place size
  // sync; for a multi-entry table the entries are collapsed into the one ramdisk
  // that now makes up the section. Keep the first entry's type, name and
  // hardware ids so the replacement stays identifiable.
  std::vector<uint8_t> vendor_table;
  size_t vendor_table_entry_num_off = npos;
  if (b == boottype::vendor_boot_img_hdr_v4 &&
      target->name == "vendor_ramdisk") {
    section *table = nullptr;
    for (section &s : sections) {
      if (s.name == "vendor_ramdisk_table") {
        table = &s;
        break;
      }
    }

    vendor_boot_img_hdr_v4 vhead{};
    if (table != nullptr && read_struct(image, 0, vhead) &&
        vhead.vendor_ramdisk_table_entry_num > 0 &&
        vhead.vendor_ramdisk_table_entry_size ==
            sizeof(vendor_ramdisk_table_entry_v4) &&
        table->size >= sizeof(vendor_ramdisk_table_entry_v4)) {
      if (vhead.vendor_ramdisk_table_entry_num > 1) {
        std::cerr << "replace: collapsing " << vhead.vendor_ramdisk_table_entry_num
                  << " vendor ramdisk table entries into one" << std::endl;
      }

      vendor_ramdisk_table_entry_v4 entry{};
      std::memcpy(&entry, table->data, sizeof(entry));
      entry.ramdisk_offset = 0;
      entry.ramdisk_size = static_cast<uint32_t>(target->size);
      vendor_table.assign(reinterpret_cast<const uint8_t *>(&entry),
                          reinterpret_cast<const uint8_t *>(&entry) +
                              sizeof(entry));

      table->data = vendor_table.data();
      table->size = vendor_table.size();
      vendor_table_entry_num_off = VENDOR_V4_TABLE_ENTRY_NUM_OFF;
    }
  }

  // Rebuild: header page(s) first, then every section page aligned. Keeping
  // the layout page-aligned means a changed section size never shifts another
  // section off its boundary.
  std::vector<uint8_t> output;
  output.resize(align_up(header_size, page), 0);
  if (header_size < image.size())
    std::memcpy(output.data(), image.data(), header_size);

  // The rewritten table has exactly one entry; its size field is updated by the
  // section loop below, but the entry count is not a section size, so write it
  // here after the header copy.
  if (vendor_table_entry_num_off != npos)
    write_le<uint32_t>(output, vendor_table_entry_num_off, 1);

  for (section &s : sections) {
    if (s.size == 0)
      continue;

    const size_t offset = output.size();
    output.resize(offset + align_up(s.size, page), 0);
    std::memcpy(output.data() + offset, s.data, s.size);

    if (s.size_field != npos)
      write_le<uint32_t>(output, s.size_field, static_cast<uint32_t>(s.size));
    if (s.offset_field != npos)
      write_le<uint64_t>(output, s.offset_field,
                         static_cast<uint64_t>(offset));
  }

  const std::string out_path = original + ".new";
  std::ofstream out(out_path, std::ios::binary);
  if (!out) {
    std::cerr << "replace: cannot write " << out_path << std::endl;
    std::remove(tmp_name.c_str());
    return -1;
  }
  out.write(reinterpret_cast<const char *>(output.data()), output.size());
  if (!out.good()) {
    std::cerr << "replace: write failed" << std::endl;
    std::remove(tmp_name.c_str());
    return -1;
  }

  std::cout << "replaced " << replaced_name << " -> " << out_path << std::endl;
  std::remove(tmp_name.c_str());
  return 0;
}

} // namespace boot
