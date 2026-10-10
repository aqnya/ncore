#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "su/su.hpp"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <pwd.h>
#include <sched.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace su {

namespace {

constexpr const char *kDefaultShell = "/system/bin/sh";
constexpr const char *kNksuBinDir = "/data/adb/nksu";

std::string base_name(const std::string &path) {
  const size_t slash = path.find_last_of('/');
  return slash == std::string::npos ? path : path.substr(slash + 1);
}

void print_usage() {
  std::cout << "Usage: su [options] [-] [user [argument...]]\n"
               "\n"
               "Options:\n"
               "  -c, --command COMMAND        pass COMMAND to the shell\n"
               "  -s, --shell SHELL            use SHELL instead of /system/bin/sh\n"
               "  -p, --preserve-environment   keep the current environment\n"
               "  -l, --login                  start a login shell\n"
               "  -M, --mount-master           run in the global mount namespace\n"
               "  -Z, --context CONTEXT        set the SELinux context\n"
               "  -v, --version                show version\n"
               "  -h, --help                   show this help\n"
            << std::endl;
}

// Append a directory to PATH if it is not there yet.
void prepend_path_dir(const std::string &dir) {
  const char *path_env = ::getenv("PATH");
  const std::string path =
      path_env != nullptr ? path_env : "/sbin:/system/sbin:/system/bin:/system/xbin";
  if (path.find(dir) != std::string::npos)
    return;
  const std::string combined = dir + ":" + path;
  ::setenv("PATH", combined.c_str(), 1);
}

void switch_to_global_mount_ns() {
  const int fd = ::open("/proc/1/ns/mnt", O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return;
  ::setns(fd, CLONE_NEWNS);
  ::close(fd);
}

void set_selinux_context(const std::string &context) {
  const int fd = ::open("/proc/self/attr/current", O_WRONLY | O_CLOEXEC);
  if (fd < 0)
    return;
  const ssize_t written = ::write(fd, context.c_str(), context.size());
  (void)written;
  ::close(fd);
}

} // namespace

bool is_su_invocation(const char *arg0) {
  return arg0 != nullptr && base_name(arg0) == "su";
}

int run(int argc, char *argv[]) {
  std::string shell;
  std::string command;
  std::string context;
  bool have_command = false;
  bool preserve_env = false;
  bool login = false;
  bool mount_master = false;
  std::vector<std::string> positional;

  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i] != nullptr ? argv[i] : "";

    if (arg == "-c" || arg == "--command") {
      if (i + 1 >= argc) {
        std::cerr << "su: option " << arg << " needs an argument" << std::endl;
        return 1;
      }
      command = argv[++i];
      have_command = true;
    } else if (arg.rfind("--command=", 0) == 0) {
      command = arg.substr(strlen("--command="));
      have_command = true;
    } else if (arg == "-s" || arg == "--shell") {
      if (i + 1 >= argc) {
        std::cerr << "su: option " << arg << " needs an argument" << std::endl;
        return 1;
      }
      shell = argv[++i];
    } else if (arg.rfind("--shell=", 0) == 0) {
      shell = arg.substr(strlen("--shell="));
    } else if (arg == "-p" || arg == "--preserve-environment") {
      preserve_env = true;
    } else if (arg == "-l" || arg == "--login" || arg == "-") {
      login = true;
    } else if (arg == "-M" || arg == "--mount-master" || arg == "-mm") {
      mount_master = true;
    } else if (arg == "-Z" || arg == "--context") {
      if (i + 1 >= argc) {
        std::cerr << "su: option " << arg << " needs an argument" << std::endl;
        return 1;
      }
      context = argv[++i];
    } else if (arg.rfind("--context=", 0) == 0) {
      context = arg.substr(strlen("--context="));
    } else if (arg == "-g" || arg == "--group" || arg == "-u" || arg == "--user") {
      if (i + 1 < argc)
        ++i; // consume and ignore: only root is supported
    } else if (arg == "-G" || arg == "--supp-group") {
      if (i + 1 < argc)
        ++i;
    } else if (arg == "--") {
      for (++i; i < argc; ++i)
        positional.push_back(argv[i] != nullptr ? argv[i] : "");
      break;
    } else if (arg == "-h" || arg == "--help") {
      print_usage();
      return 0;
    } else if (arg == "-v" || arg == "--version") {
      std::cout << "ncore su 1.0.0" << std::endl;
      return 0;
    } else if (!arg.empty() && arg[0] == '-' && arg != "-") {
      std::cerr << "su: unknown option: " << arg << std::endl;
      return 1;
    } else {
      positional.push_back(arg);
    }
  }

  // Only root is supported: the kernel always escalates to root before we run.
  if (!positional.empty()) {
    const std::string &user = positional[0];
    if (user != "root" && user != "0") {
      std::cerr << "su: only root is supported" << std::endl;
      return 1;
    }
  }

  if (::geteuid() != 0 && ::setuid(0) != 0) {
    std::cerr << "su: cannot switch to root: " << std::strerror(errno)
              << std::endl;
    return 1;
  }

  if (shell.empty())
    shell = kDefaultShell;

  if (mount_master)
    switch_to_global_mount_ns();

  if (!preserve_env) {
    const struct passwd *pw = ::getpwuid(0);
    const std::string home = (pw != nullptr && pw->pw_dir != nullptr) ? pw->pw_dir : "/";
    const std::string name = (pw != nullptr && pw->pw_name != nullptr) ? pw->pw_name : "root";
    ::setenv("HOME", home.c_str(), 1);
    ::setenv("USER", name.c_str(), 1);
    ::setenv("LOGNAME", name.c_str(), 1);
    ::setenv("SHELL", shell.c_str(), 1);
  }

  prepend_path_dir(kNksuBinDir);
  ::umask(022);

  if (!context.empty())
    set_selinux_context(context);

  std::vector<char *> args;
  std::string arg0 = login ? "-" : shell;
  args.push_back(const_cast<char *>(arg0.c_str()));
  if (have_command) {
    args.push_back(const_cast<char *>("-c"));
    args.push_back(const_cast<char *>(command.c_str()));
  }
  args.push_back(nullptr);

  ::execv(shell.c_str(), args.data());
  std::cerr << "su: cannot execute " << shell << ": " << std::strerror(errno)
            << std::endl;
  return 127;
}

} // namespace su
