#include "cli.hpp"
#include "argparse/argparse.hpp"
#include "boot/boot.hpp"
#include "module/module.hpp"
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

namespace cli {

constexpr const char *kVersion = "ncore 1.0.0";

namespace {

// Trigger a module init event. KernelSU installs ksud as the handler for the
// init.rc `exec` actions; ncore exposes the same entry points as subcommands.
int run_module_event(const char *event) {
  const std::string stage(event);
  if (stage == "post-fs-data")
    return modules::on_post_fs_data();
  if (stage == "service")
    return modules::on_services();
  if (stage == "boot-completed")
    return modules::on_boot_completed();
  return 1;
}

int run_module_command(argparse::ArgumentParser &program) {
  auto &module_cmd = program.at<argparse::ArgumentParser>("module");

  if (module_cmd.is_subcommand_used("list"))
    return modules::list_modules();

  if (module_cmd.is_subcommand_used("enable"))
    return modules::enable_module(
        module_cmd.at<argparse::ArgumentParser>("enable").get<std::string>(
            "id"));

  if (module_cmd.is_subcommand_used("disable"))
    return modules::disable_module(
        module_cmd.at<argparse::ArgumentParser>("disable").get<std::string>(
            "id"));

  if (module_cmd.is_subcommand_used("uninstall"))
    return modules::uninstall_module(
        module_cmd.at<argparse::ArgumentParser>("uninstall").get<std::string>(
            "id"));

  if (module_cmd.is_subcommand_used("undo-uninstall"))
    return modules::undo_uninstall_module(
        module_cmd.at<argparse::ArgumentParser>("undo-uninstall")
            .get<std::string>("id"));

  if (module_cmd.is_subcommand_used("action"))
    return modules::run_action(
        module_cmd.at<argparse::ArgumentParser>("action").get<std::string>(
            "id"));

  std::cerr << module_cmd << std::endl;
  return 1;
}

} // namespace

int parse_cli(int argc, char *argv[], arguments &args) {
  (void)args;

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

  // --- init events ---------------------------------------------------------
  argparse::ArgumentParser post_fs_data("post-fs-data");
  post_fs_data.add_description("trigger the `post-fs-data` init event");
  program.add_subparser(post_fs_data);

  argparse::ArgumentParser services("services");
  services.add_description("trigger the `service` init event");
  program.add_subparser(services);

  argparse::ArgumentParser boot_completed("boot-completed");
  boot_completed.add_description("trigger the `boot-completed` init event");
  program.add_subparser(boot_completed);

  // --- daemon installation -------------------------------------------------
  argparse::ArgumentParser install("install");
  install.add_description("install the ncore daemon to its boot path");
  program.add_subparser(install);

  // --- module management ---------------------------------------------------
  argparse::ArgumentParser module_cmd("module");
  module_cmd.add_description("manage modules");

  argparse::ArgumentParser module_list("list");
  module_list.add_description("list installed modules");
  module_cmd.add_subparser(module_list);

  argparse::ArgumentParser module_enable("enable");
  module_enable.add_description("enable module <id>");
  module_enable.add_argument("id").help("module id");
  module_cmd.add_subparser(module_enable);

  argparse::ArgumentParser module_disable("disable");
  module_disable.add_description("disable module <id>");
  module_disable.add_argument("id").help("module id");
  module_cmd.add_subparser(module_disable);

  argparse::ArgumentParser module_uninstall("uninstall");
  module_uninstall.add_description("mark module <id> for removal");
  module_uninstall.add_argument("id").help("module id");
  module_cmd.add_subparser(module_uninstall);

  argparse::ArgumentParser module_undo("undo-uninstall");
  module_undo.add_description("clear the removal mark of module <id>");
  module_undo.add_argument("id").help("module id");
  module_cmd.add_subparser(module_undo);

  argparse::ArgumentParser module_action("action");
  module_action.add_description("run <id>/action.sh");
  module_action.add_argument("id").help("module id");
  module_cmd.add_subparser(module_action);

  program.add_subparser(module_cmd);

  // --- initrc --------------------------------------------------------------
  argparse::ArgumentParser initrc("initrc");
  initrc.add_description("manage initrc injection");

  argparse::ArgumentParser initrc_refresh("refresh");
  initrc_refresh.add_description("regenerate the preinit modules.rc");
  initrc.add_subparser(initrc_refresh);
  program.add_subparser(initrc);

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

  // --- init events ---------------------------------------------------------
  if (program.is_subcommand_used("post-fs-data"))
    return run_module_event("post-fs-data");
  if (program.is_subcommand_used("services"))
    return run_module_event("service");
  if (program.is_subcommand_used("boot-completed"))
    return run_module_event("boot-completed");

  if (program.is_subcommand_used("install"))
    return modules::install();

  // --- module management ---------------------------------------------------
  if (program.is_subcommand_used("module"))
    return run_module_command(program);

  if (program.is_subcommand_used("initrc")) {
    auto &initrc_cmd = program.at<argparse::ArgumentParser>("initrc");
    if (initrc_cmd.is_subcommand_used("refresh"))
      return modules::refresh_initrc();
    std::cerr << initrc_cmd << std::endl;
    return 1;
  }

  // --- boot image tools ----------------------------------------------------
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
