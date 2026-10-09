#include "module_internal.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#if defined(__ANDROID__)
#include <sys/system_properties.h>
#endif

namespace modules {

namespace defs {

namespace {

std::string env_or(const char *name, const std::string &fallback) {
  const char *value = ::getenv(name);
  return (value != nullptr && *value != '\0') ? std::string(value) : fallback;
}

std::string with_trailing_slash(std::string value) {
  if (!value.empty() && value.back() != '/')
    value += '/';
  return value;
}

} // namespace

const std::string &adb_dir() {
  static const std::string value =
      with_trailing_slash(env_or("NCORE_ADB_DIR", DEFAULT_ADB_DIR));
  return value;
}

const std::string &working_dir() {
  static const std::string value =
      with_trailing_slash(env_or("NCORE_WORKING_DIR", adb_dir() + "ksu/"));
  return value;
}

const std::string &binary_dir() {
  static const std::string value = working_dir() + "bin/";
  return value;
}

const std::string &log_dir() {
  static const std::string value = working_dir() + "log/";
  return value;
}

const std::string &module_dir() {
  static const std::string value = adb_dir() + "modules/";
  return value;
}

const std::string &module_update_dir() {
  static const std::string value = adb_dir() + "modules_update/";
  return value;
}

const std::string &metamodule_dir() {
  static const std::string value = adb_dir() + "metamodule/";
  return value;
}

const std::string &busybox_path() {
  static const std::string value = binary_dir() + "busybox";
  return value;
}

const std::string &preinit_dir_watchdog() {
  static const std::string value = with_trailing_slash(
      env_or("NCORE_PREINIT_DIR_WATCHDOG", DEFAULT_PREINIT_DIR_WATCHDOG));
  return value;
}

const std::string &preinit_dir_default() {
  static const std::string value = with_trailing_slash(
      env_or("NCORE_PREINIT_DIR_DEFAULT", DEFAULT_PREINIT_DIR_DEFAULT));
  return value;
}

const std::string &sepolicy_sink() {
  static const std::string value =
      env_or("NCORE_SEPOLICY_SINK", "/proc/nksu/sepolicy");
  return value;
}

const std::string &boot_path() {
  static const std::string value =
      env_or("NCORE_BOOT_PATH", "/data/adb/nksu/ncore");
  return value;
}

} // namespace defs

namespace utils {

std::string getprop(const std::string &name) {
#if defined(__ANDROID__)
  char value[PROP_VALUE_MAX] = {0};
  __system_property_get(name.c_str(), value);
  return std::string(value);
#else
  (void)name;
  return std::string();
#endif
}

bool setprop(const std::string &name, const std::string &value) {
#if defined(__ANDROID__)
  return __system_property_set(name.c_str(), value.c_str()) == 0;
#else
  (void)name;
  (void)value;
  return false;
#endif
}

bool exists(const std::string &path) {
  struct stat st {};
  return ::lstat(path.c_str(), &st) == 0;
}

bool is_dir(const std::string &path) {
  struct stat st {};
  return ::stat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}

bool is_file(const std::string &path) {
  struct stat st {};
  return ::stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}

bool is_symlink(const std::string &path) {
  struct stat st {};
  return ::lstat(path.c_str(), &st) == 0 && S_ISLNK(st.st_mode);
}

bool is_executable(const std::string &path) {
  return is_file(path) && ::access(path.c_str(), X_OK) == 0;
}

std::string which(const std::string &name) {
  if (name.empty())
    return std::string();

  if (name.find('/') != std::string::npos)
    return is_executable(name) ? name : std::string();

  const char *path_env = ::getenv("PATH");
  if (path_env == nullptr)
    return std::string();

  const std::string path(path_env);
  size_t start = 0;
  while (start <= path.size()) {
    const size_t end = path.find(':', start);
    const std::string dir = path.substr(
        start, end == std::string::npos ? std::string::npos : end - start);
    if (!dir.empty()) {
      const std::string candidate = dir + "/" + name;
      if (is_executable(candidate))
        return candidate;
    }
    if (end == std::string::npos)
      break;
    start = end + 1;
  }
  return std::string();
}

bool is_safe_mode() {
  return getprop("persist.sys.safemode") == "1" ||
         getprop("ro.sys.safemode") == "1";
}

bool has_magisk() { return !which("magisk").empty(); }

void umask0() { ::umask(0); }

void detach_process_group(bool use_init_pgrp) {
  // The kernel-side "init process group" supercall does not exist in ncore, so
  // we always fall back to creating a fresh process group, matching ksud's
  // fallback path when the supercall fails.
  (void)use_init_pgrp;
  ::setpgid(0, 0);
}

namespace {

void switch_cgroup(const std::string &group, int pid) {
  const std::string path = group + "/cgroup.procs";
  const int fd = ::open(path.c_str(), O_WRONLY | O_APPEND | O_CLOEXEC);
  if (fd < 0)
    return;

  const std::string value = std::to_string(pid);
  const ssize_t written = ::write(fd, value.c_str(), value.size());
  (void)written;
  ::close(fd);
}

} // namespace

void switch_cgroups() {
  const int pid = ::getpid();
  switch_cgroup("/acct", pid);
  switch_cgroup("/dev/cg2_bpf", pid);
  switch_cgroup("/sys/fs/cgroup", pid);

  if (getprop("ro.config.per_app_memcg") != "false")
    switch_cgroup("/dev/memcg/apps", pid);
}

bool ensure_dir_exists(const std::string &dir) {
  if (dir.empty())
    return false;

  std::string path;
  size_t i = 0;
  if (dir[0] == '/') {
    path = "/";
    i = 1;
  }

  while (i < dir.size()) {
    const size_t slash = dir.find('/', i);
    const std::string component =
        dir.substr(i, slash == std::string::npos ? std::string::npos
                                                 : slash - i);
    if (!component.empty()) {
      if (path.empty() || path.back() != '/')
        path += '/';
      path += component;
      if (::mkdir(path.c_str(), 0777) != 0 && errno != EEXIST)
        return false;
    }
    if (slash == std::string::npos)
      break;
    i = slash + 1;
  }
  return is_dir(dir);
}

bool ensure_file_exists(const std::string &file) {
  const int fd =
      ::open(file.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
  if (fd >= 0) {
    ::close(fd);
    return true;
  }
  if (errno == EEXIST && is_file(file))
    return true;
  return false;
}

bool remove_dir_all(const std::string &path) {
  struct stat st {};
  if (::lstat(path.c_str(), &st) != 0)
    return errno == ENOENT;

  if (!S_ISDIR(st.st_mode))
    return ::unlink(path.c_str()) == 0;

  DIR *dir = ::opendir(path.c_str());
  if (dir == nullptr)
    return false;

  bool ok = true;
  struct dirent *entry = nullptr;
  while ((entry = ::readdir(dir)) != nullptr) {
    const std::string name(entry->d_name);
    if (name == "." || name == "..")
      continue;
    if (!remove_dir_all(path + "/" + name))
      ok = false;
  }
  ::closedir(dir);

  if (::rmdir(path.c_str()) != 0)
    ok = false;
  return ok;
}

bool ensure_clean_dir(const std::string &dir) {
  remove_dir_all(dir);
  return ensure_dir_exists(dir);
}

bool read_file(const std::string &path, std::string &out) {
  std::ifstream in(path, std::ios::binary);
  if (!in)
    return false;
  std::ostringstream buffer;
  buffer << in.rdbuf();
  out = buffer.str();
  return true;
}

bool write_file(const std::string &path, const std::string &data, bool append) {
  std::ofstream out(path, std::ios::binary |
                              (append ? std::ios::app : std::ios::trunc));
  if (!out)
    return false;
  out.write(data.data(), static_cast<std::streamsize>(data.size()));
  return out.good();
}

bool rename_path(const std::string &from, const std::string &to) {
  return ::rename(from.c_str(), to.c_str()) == 0;
}

bool read_link(const std::string &path, std::string &out) {
  char buffer[4096];
  const ssize_t len = ::readlink(path.c_str(), buffer, sizeof(buffer) - 1);
  if (len < 0)
    return false;
  buffer[len] = '\0';
  out.assign(buffer, static_cast<size_t>(len));
  return true;
}

std::vector<std::string> list_dir(const std::string &dir) {
  std::vector<std::string> entries;
  DIR *handle = ::opendir(dir.c_str());
  if (handle == nullptr)
    return entries;

  struct dirent *entry = nullptr;
  while ((entry = ::readdir(handle)) != nullptr) {
    const std::string name(entry->d_name);
    if (name == "." || name == "..")
      continue;
    entries.push_back(name);
  }
  ::closedir(handle);

  std::sort(entries.begin(), entries.end());
  return entries;
}

std::string base_name(const std::string &path) {
  const std::string trimmed = strip_trailing_slash(path);
  const size_t slash = trimmed.find_last_of('/');
  if (slash == std::string::npos)
    return trimmed;
  return trimmed.substr(slash + 1);
}

std::string dir_name(const std::string &path) {
  const std::string trimmed = strip_trailing_slash(path);
  const size_t slash = trimmed.find_last_of('/');
  if (slash == std::string::npos)
    return std::string();
  if (slash == 0)
    return "/";
  return trimmed.substr(0, slash);
}

std::string join(const std::string &dir, const std::string &name) {
  if (dir.empty())
    return name;
  if (dir.back() == '/')
    return dir + name;
  return dir + "/" + name;
}

std::string strip_trailing_slash(const std::string &path) {
  std::string result = path;
  while (result.size() > 1 && result.back() == '/')
    result.pop_back();
  return result;
}

std::string realpath_str(const std::string &path) {
  char resolved[4096];
  if (::realpath(path.c_str(), resolved) == nullptr)
    return std::string();
  return std::string(resolved);
}

std::string trim(const std::string &value) {
  const char *whitespace = " \t\r\n";
  const size_t begin = value.find_first_not_of(whitespace);
  if (begin == std::string::npos)
    return std::string();
  const size_t end = value.find_last_not_of(whitespace);
  return value.substr(begin, end - begin + 1);
}

} // namespace utils
} // namespace modules
