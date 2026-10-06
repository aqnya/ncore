#include "boot_internal.hpp"
#include "bootimg.h"
#include <cstring>

enum class btype : uint8_t {
  vendor_boot,
  boot,
  invalid,
};

namespace boot {
namespace {

constexpr auto offset = offsetof(boot_img_hdr_v0, header_version);

btype check_head(const uint8_t *data) {
  if (std::memcmp(data, BOOT_MAGIC, 8) == 0) {
    return btype::boot;
  } else if (std::memcmp(data, VENDOR_BOOT_MAGIC, 8) == 0) {
    return btype::vendor_boot;
  }
  return btype::invalid;
}
} // namespace
boottype probe_type(MMapFile &bootimg) {
  uint32_t header_version;
  switch (check_head(bootimg.data())) {
  case btype::invalid:
    return boottype::invalid;
  case btype::vendor_boot: {
    if (bootimg.size() < VENDOR_BOOT_MAGIC_SIZE + 4)
      return boottype::invalid;
    std::memcpy(&header_version, bootimg.data() + VENDOR_BOOT_MAGIC_SIZE, 4);
    if (header_version == 4)
      return boottype::vendor_boot_img_hdr_v4;
    if (header_version == 3)
      return boottype::vendor_boot_img_hdr_v3;
    return boottype::invalid;
  }
  case btype::boot: {
    if (bootimg.size() < offset + 4)
      return boottype::invalid;
    std::memcpy(&header_version, bootimg.data() + offset, 4);
    switch (header_version) {
    case 0:
      return boottype::boot_img_hdr_v0;
    case 1:
      return boottype::boot_img_hdr_v1;
    case 2:
      return boottype::boot_img_hdr_v2;
    case 3:
      return boottype::boot_img_hdr_v3;
    case 4:
      return boottype::boot_img_hdr_v4;
    default:
      return boottype::invalid;
    }
  }
  }
}
} // namespace boot