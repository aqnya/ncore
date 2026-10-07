#include "cli.hpp"
#include "argparse/argparse.hpp"
#include "boot/boot.hpp"
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

namespace cli {

constexpr const char *kVersion = "ncore 1.0.0";

int parse_cli(int argc, char *argv[], arguments &args) {
  argparse::ArgumentParser program("ncore", kVersion,
                                   argparse::default_arguments::none);
  program.add_description("ncore -- nekosu userspace tools.");

  program.add_argument("-h", "--help")
      .help("shows help message and exits")
      .default_value(false)
      .implicit_value(true)
      .hidden_from_usage();

  program.add_argument("-v", "--version")
      .help("show version")
      .default_value(false)
      .implicit_value(true)
      .hidden_from_usage();
  program.add_argument("-u", "--unpack")
    .help("unpack bootimg")
    .nargs(1)
    .metavar("PATH")
    .hidden_from_usage();
  
  program.add_argument("-r", "--replace")
    .help("replace bootimg: <boot.img> <kernel/dtb>")
    .nargs(2)
    .metavar("<bootimg> <kernel/dtb>")
    .hidden_from_usage();

  if (argc <= 1) {
    std::cout << program << std::endl;
    return 0;
  }

  try {
    program.parse_args(argc, argv);
  } catch (const std::exception &e) {
    std::cerr << e.what() << "\n\n" << program;
    return 1;
  }

  if (program.get<bool>("--help")) {
    std::cout << program << std::endl;
    return 0;
  }
  if (program.get<bool>("--version")) {
    std::cout << kVersion << std::endl;
    return 0;
  }
  
  if (program.is_used("--unpack")) {
    std::string path = program.get<std::string>("--unpack");
    int ret = boot::unpack(path);
    if (ret < 0)
      return -1;
    return 0;
}

  if (program.is_used("--replace")) {
    auto files = program.get<std::vector<std::string>>("--replace");
    if (files.size() < 2) {
      std::cerr << "--replace requires <bootimg> <kernel/dtb>\n";
      return 1;
    }
    int ret = boot::replace(files[0], files[1]);
    if (ret < 0)
      return -1;
    return 0;
}

  return 0;
}

} // namespace cli