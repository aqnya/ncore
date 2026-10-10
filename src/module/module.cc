#include "module_internal.hpp"
#include "zip.hpp"

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <iostream>
#include <map>
#include <sstream>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

// Userspace module runtime, ported from KernelSU's ksud. The behaviour of each
// stage follows userspace/ksud/src/module.rs (script execution, module
// iteration and lifecycle) and userspace/ksud/src/init_event.rs (init events).
namespace modules {

namespace {

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

std::string to_lower(const std::string &value) {
  std::string result = value;
  for (char &c : result) {
    if (c >= 'A' && c <= 'Z')
      c = static_cast<char>(c - 'A' + 'a');
  }
  return result;
}

bool is_alpha(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

bool is_digit(char c) { return c >= '0' && c <= '9'; }

std::vector<std::string> inherited_env() {
  std::vector<std::string> env;
  for (char **entry = ::environ; entry != nullptr && *entry != nullptr;
       ++entry)
    env.emplace_back(*entry);
  return env;
}

void set_env(std::vector<std::string> &env, const std::string &key,
             const std::string &value) {
  const std::string prefix = key + "=";
  for (auto &entry : env) {
    if (entry.compare(0, prefix.size(), prefix) == 0) {
      entry = prefix + value;
      return;
    }
  }
  env.push_back(prefix + value);
}

std::string get_env(const std::vector<std::string> &env,
                    const std::string &key) {
  const std::string prefix = key + "=";
  for (const auto &entry : env) {
    if (entry.compare(0, prefix.size(), prefix) == 0)
      return entry.substr(prefix.size());
  }
  return std::string();
}

// Parse a java-properties style file (module.prop / system.prop / persist.config
// all use the same `key=value` shape as the Rust `java_properties` crate that
// ksud parses these with).
void parse_properties(const std::string &content, Properties &out) {
  out.clear();
  std::istringstream stream(content);
  std::string line;
  while (std::getline(stream, line)) {
    const std::string trimmed = utils::trim(line);
    if (trimmed.empty() || trimmed[0] == '#')
      continue;
    const size_t eq = trimmed.find('=');
    if (eq == std::string::npos)
      continue;
    const std::string key = utils::trim(trimmed.substr(0, eq));
    const std::string value = utils::trim(trimmed.substr(eq + 1));
    if (!key.empty())
      out.emplace_back(key, value);
  }
}

// Environment exported to every module script, mirroring
// get_common_script_envs() in ksud.
std::vector<std::string> build_env(const std::string &module_id) {
  std::vector<std::string> env = inherited_env();
  set_env(env, "ASH_STANDALONE", "1");
  set_env(env, "KSU", "true");
  set_env(env, "KSU_KERNEL_VER_CODE", "0");
  set_env(env, "KSU_VER_CODE", defs::KSU_VERSION_CODE);
  set_env(env, "KSU_VER", defs::KSU_VERSION_NAME);
  set_env(env, "KSU_UAPI_VER", defs::KSU_UAPI_VERSION);
  set_env(env, "KSU_RUNTIME_MODE", defs::KSU_RUNTIME_MODE);

  const std::string existing = get_env(env, "PATH");
  const std::string binary_dir =
      utils::strip_trailing_slash(defs::binary_dir());
  set_env(env, "PATH",
          existing.empty() ? binary_dir : existing + ":" + binary_dir);

  if (!module_id.empty())
    set_env(env, "KSU_MODULE", module_id);

  return env;
}

// Resolve the script interpreter. ncore ships its own busybox under its runtime
// directory (/data/adb/nksu/bin/busybox); fall back to busybox on PATH and
// finally the system shell.
struct ShellSpec {
  std::string program;
  std::vector<std::string> argv; // argv[0] included
};

ShellSpec resolve_shell(const std::string &script) {
  if (utils::is_executable(defs::busybox_path()))
    return {defs::busybox_path(), {"busybox", "sh", script}};

  const std::string busybox = utils::which("busybox");
  if (!busybox.empty())
    return {busybox, {"busybox", "sh", script}};

  if (utils::is_executable(defs::SYSTEM_SH_PATH))
    return {defs::SYSTEM_SH_PATH, {"sh", script}};

  const std::string sh = utils::which("sh");
  if (!sh.empty())
    return {sh, {"sh", script}};

  return {std::string(), {}};
}

bool wait_forever(pid_t pid, int *exit_code = nullptr) {
  int status = 0;
  while (::waitpid(pid, &status, 0) < 0) {
    if (errno != EINTR)
      return false;
  }

  if (exit_code != nullptr) {
    if (WIFEXITED(status))
      *exit_code = WEXITSTATUS(status);
    else if (WIFSIGNALED(status))
      *exit_code = 128 + WTERMSIG(status);
    else
      *exit_code = -1;
  }
  return true;
}

bool wait_until(pid_t pid, const Deadline &deadline) {
  for (;;) {
    int status = 0;
    const pid_t result = ::waitpid(pid, &status, WNOHANG);
    if (result == pid)
      return true;
    if (result < 0 && errno != EINTR)
      return false;

    if (std::chrono::steady_clock::now() >= deadline)
      return false;

    struct timespec interval {};
    interval.tv_sec = 0;
    interval.tv_nsec = 10 * 1000 * 1000; // 10ms
    ::nanosleep(&interval, nullptr);
  }
}

std::string extract_module_id(const std::string &path) {
  const std::string root = defs::module_dir();
  if (path.compare(0, root.size(), root) != 0)
    return std::string();

  const std::string rest = path.substr(root.size());
  const size_t slash = rest.find('/');
  const std::string id =
      slash == std::string::npos ? rest : rest.substr(0, slash);
  return validate_module_id(id) ? id : std::string();
}

std::string preinit_dir() {
  const std::string watchdog_parent = utils::dir_name(
      utils::strip_trailing_slash(defs::preinit_dir_watchdog()));
  if (utils::is_dir(watchdog_parent))
    return defs::preinit_dir_watchdog();
  return defs::preinit_dir_default();
}

void collect_rc_files(const std::string &dir, const std::string &module_id,
                      std::string &out) {
  if (!utils::is_dir(dir))
    return;

  for (const auto &name : utils::list_dir(dir)) {
    const std::string path = utils::join(dir, name);
    if (!utils::is_file(path))
      continue;
    const size_t dot = name.find_last_of('.');
    if (dot == std::string::npos || name.substr(dot) != ".rc")
      continue;

    if (module_id.empty()) {
      // Common initrc.d files use the executable bit as an on/off switch.
      if (!utils::is_executable(path))
        continue;
      out += "# === from " + path + " ===\n";
    } else {
      out += "# === from " + module_id + ":" + path + " ===\n";
    }

    std::string content;
    if (utils::read_file(path, content)) {
      out += content;
      if (out.empty() || out.back() != '\n')
        out += '\n';
    }
  }
}

void mark_all_modules(const std::string &flag) {
  if (!utils::is_dir(defs::module_dir()))
    return;
  for (const auto &name : utils::list_dir(defs::module_dir())) {
    const std::string path = utils::join(defs::module_dir(), name);
    if (!utils::is_dir(path))
      continue;
    if (!utils::ensure_file_exists(utils::join(path, flag)))
      std::cerr << "[module] failed to mark " << path << std::endl;
  }
}

void run_stage_internal(const std::string &stage, ScriptWait wait,
                        const Deadline &deadline) {
  utils::umask0();

  if (utils::has_magisk()) {
    std::cerr << "[module] Magisk detected, skip " << stage << std::endl;
    return;
  }
  if (utils::is_safe_mode()) {
    std::cerr << "[module] safe mode, skip " << stage << " scripts" << std::endl;
    return;
  }

  exec_common_scripts(stage + ".d", wait, deadline);
  // Metamodule stage scripts take priority over regular modules.
  metamodule_exec_stage_script(stage, wait, deadline);
  exec_stage_script(stage, wait, deadline);
}

} // namespace

// ---------------------------------------------------------------------------
// Module iteration and properties
// ---------------------------------------------------------------------------

bool validate_module_id(const std::string &id) {
  if (id.size() < 2 || !is_alpha(id[0]))
    return false;
  for (size_t i = 1; i < id.size(); ++i) {
    const char c = id[i];
    if (is_alpha(c) || is_digit(c) || c == '.' || c == '_' || c == '-')
      continue;
    return false;
  }
  return true;
}

bool read_module_prop(const std::string &module_path, Properties &out) {
  std::string content;
  if (!utils::read_file(utils::join(module_path, defs::MODULE_PROP), content))
    return false;

  parse_properties(content, out);
  return true;
}

std::string prop_get(const Properties &props, const std::string &key) {
  for (const auto &entry : props) {
    if (entry.first == key)
      return entry.second;
  }
  return std::string();
}

void foreach_module(ModuleType type, const ModuleVisitor &visitor) {
  const std::string root =
      type == ModuleType::Updated ? defs::module_update_dir() : defs::module_dir();
  if (!utils::is_dir(root))
    return;

  for (const auto &name : utils::list_dir(root)) {
    const std::string path = utils::join(root, name);
    if (!utils::is_dir(path))
      continue;

    if (type == ModuleType::Active) {
      if (utils::exists(utils::join(path, defs::DISABLE_FILE_NAME)))
        continue;
      if (utils::exists(utils::join(path, defs::REMOVE_FILE_NAME)))
        continue;
    }
    visitor(path);
  }
}

// ---------------------------------------------------------------------------
// Script execution
// ---------------------------------------------------------------------------

void exec_script(
    const std::string &path, ScriptWait wait, const Deadline &deadline,
    const std::vector<std::pair<std::string, std::string>> &extra_env,
    int *exit_code) {
  if (exit_code != nullptr)
    *exit_code = -1;

  if (!utils::is_file(path)) {
    std::cerr << "[module] script not found: " << path << std::endl;
    return;
  }

  const std::string module_id = extract_module_id(path);
  const ShellSpec shell = resolve_shell(path);
  if (shell.program.empty()) {
    std::cerr << "[module] no usable shell (busybox/sh) for " << path
              << std::endl;
    return;
  }

  std::cout << "[module] exec " << path << std::endl;

  std::vector<std::string> env = build_env(module_id);
  for (const auto &entry : extra_env)
    set_env(env, entry.first, entry.second);

  std::vector<char *> argv;
  for (auto &arg : shell.argv)
    argv.push_back(const_cast<char *>(arg.c_str()));
  argv.push_back(nullptr);

  std::vector<char *> envp;
  for (auto &entry : env)
    envp.push_back(const_cast<char *>(entry.c_str()));
  envp.push_back(nullptr);

  const std::string cwd = utils::dir_name(path);

  const pid_t pid = ::fork();
  if (pid < 0) {
    std::cerr << "[module] fork failed: " << std::strerror(errno)
              << std::endl;
    return;
  }

  if (pid == 0) {
    utils::detach_process_group(false);
    utils::switch_cgroups();
    if (!cwd.empty())
      ::chdir(cwd.c_str());
    ::execve(shell.program.c_str(), argv.data(), envp.data());
    std::cerr << "[module] exec failed: " << shell.program << ": "
              << std::strerror(errno) << std::endl;
    ::_exit(127);
  }

  switch (wait) {
  case ScriptWait::NoWait:
    if (exit_code != nullptr)
      *exit_code = 0; // not waited for, so no status is available
    break;
  case ScriptWait::Forever:
    wait_forever(pid, exit_code);
    break;
  case ScriptWait::Until:
    if (deadline > std::chrono::steady_clock::now() &&
        !wait_until(pid, deadline)) {
      std::cerr << "[module] timed out waiting for script: " << path
                << std::endl;
    }
    break;
  }
}

void exec_stage_script(const std::string &stage, ScriptWait wait,
                       const Deadline &deadline) {
  const std::string metamodule = utils::realpath_str(get_metamodule_path());

  foreach_module(ModuleType::Active, [&](const std::string &module) {
    // The metamodule stage script runs separately, with priority.
    if (!metamodule.empty() &&
        utils::realpath_str(module) == metamodule) {
      return;
    }
    const std::string script = utils::join(module, stage + ".sh");
    if (utils::is_file(script))
      exec_script(script, wait, deadline);
  });
}

void exec_common_scripts(const std::string &dir, ScriptWait wait,
                         const Deadline &deadline) {
  const std::string script_dir = utils::join(defs::adb_dir(), dir);
  if (!utils::is_dir(script_dir)) {
    std::cout << "[module] " << script_dir << " not exists, skip" << std::endl;
    return;
  }

  for (const auto &name : utils::list_dir(script_dir)) {
    const std::string path = utils::join(script_dir, name);
    if (!utils::is_executable(path)) {
      std::cerr << "[module] " << path << " is not executable, skip"
                << std::endl;
      continue;
    }
    exec_script(path, wait, deadline);
  }
}

// ---------------------------------------------------------------------------
// Metamodule support
// ---------------------------------------------------------------------------

bool is_metamodule(const Properties &props) {
  const std::string value = to_lower(prop_get(props, "metamodule"));
  return value == "1" || value == "true";
}

std::string get_metamodule_path() {
  const std::string link = utils::strip_trailing_slash(defs::metamodule_dir());
  if (utils::is_symlink(link)) {
    std::string target;
    if (utils::read_link(link, target) && !target.empty()) {
      if (target[0] != '/')
        target = utils::join(utils::dir_name(link), target);
      if (utils::is_dir(target))
        return target;
      std::cerr << "[module] metamodule symlink points to a missing path: "
                << target << std::endl;
    }
  }

  // Fallback: scan the module directory for metamodule=1. Keep the last match,
  // as ksud does, so a later module wins a metamodule id collision.
  std::string found;
  foreach_module(ModuleType::All, [&found](const std::string &module) {
    Properties props;
    if (read_module_prop(module, props) && is_metamodule(props))
      found = module;
  });
  return found;
}

std::string get_metamodule_id() {
  const std::string path = get_metamodule_path();
  return path.empty() ? std::string() : utils::base_name(path);
}

void metamodule_exec_stage_script(const std::string &stage, ScriptWait wait,
                                  const Deadline &deadline) {
  const std::string path = get_metamodule_path();
  if (path.empty() || utils::exists(utils::join(path, defs::DISABLE_FILE_NAME)))
    return;

  const std::string script = utils::join(path, stage + ".sh");
  if (utils::is_file(script))
    exec_script(script, wait, deadline);
}

void metamodule_exec_mount_script() {
  const std::string path = get_metamodule_path();
  if (path.empty() || utils::exists(utils::join(path, defs::DISABLE_FILE_NAME)))
    return;

  const std::string script = utils::join(path, defs::METAMODULE_MOUNT_SCRIPT);
  if (!utils::is_file(script))
    return;

  exec_script(script, ScriptWait::Forever, std::chrono::steady_clock::now(),
              {{"MODULE_DIR", defs::module_dir()}});
}

void metamodule_remove_symlink() {
  const std::string link = utils::strip_trailing_slash(defs::metamodule_dir());
  if (utils::is_symlink(link))
    ::unlink(link.c_str());
}

void metamodule_exec_metauninstall_script(const std::string &module_id) {
  const std::string path = get_metamodule_path();
  if (path.empty() || utils::exists(utils::join(path, defs::DISABLE_FILE_NAME)))
    return;

  const std::string script =
      utils::join(path, defs::METAMODULE_METAUNINSTALL_SCRIPT);
  if (!utils::is_file(script))
    return;

  std::cout << "[module] metamodule metauninstall for " << module_id
            << std::endl;
  exec_script(script, ScriptWait::Forever, std::chrono::steady_clock::now(),
              {{"MODULE_ID", module_id}});
}

namespace {

// A metamodule only overrides the install flow when it ships a metainstall.sh,
// looking at both the active module and its staged update.
bool metamodule_has_metainstall() {
  const std::string path = get_metamodule_path();
  if (path.empty())
    return false;
  if (utils::is_file(utils::join(path, defs::METAMODULE_METAINSTALL_SCRIPT)))
    return true;

  const std::string id = utils::base_name(path);
  return utils::is_file(
      utils::join(utils::join(defs::module_update_dir(), id),
                  defs::METAMODULE_METAINSTALL_SCRIPT));
}

} // namespace

bool metamodule_check_install_safety(bool *disabled) {
  if (disabled != nullptr)
    *disabled = false;

  const std::string path = get_metamodule_path();
  if (path.empty())
    return true;

  // No metainstall.sh means the default installer is used: always safe.
  if (!metamodule_has_metainstall())
    return true;

  const bool has_update = utils::exists(utils::join(path, defs::UPDATE_FILE_NAME));
  const bool has_remove = utils::exists(utils::join(path, defs::REMOVE_FILE_NAME));
  const bool has_disable =
      utils::exists(utils::join(path, defs::DISABLE_FILE_NAME));

  if (!has_update && !has_remove && !has_disable)
    return true;

  if (disabled != nullptr)
    *disabled = has_disable && !has_update && !has_remove;
  return false;
}

bool metamodule_ensure_symlink(const std::string &module_path) {
  const std::string link = utils::strip_trailing_slash(defs::metamodule_dir());

  if (utils::is_symlink(link) || utils::is_file(link)) {
    ::unlink(link.c_str());
  } else if (utils::is_dir(link)) {
    utils::remove_dir_all(link);
  }

  if (::symlink(module_path.c_str(), link.c_str()) != 0) {
    std::cerr << "[module] failed to create metamodule symlink " << link << " -> "
              << module_path << ": " << std::strerror(errno) << std::endl;
    return false;
  }
  std::cout << "[module] metamodule symlink " << link << " -> " << module_path
            << std::endl;
  return true;
}

// ---------------------------------------------------------------------------
// Init events
// ---------------------------------------------------------------------------

int on_post_fs_data() {
  utils::umask0();

  if (utils::has_magisk()) {
    std::cerr << "[module] Magisk detected, skip post-fs-data" << std::endl;
    return 0;
  }

  const bool safe_mode = utils::is_safe_mode();
  const ScriptWait wait = ScriptWait::Until;
  const Deadline deadline = std::chrono::steady_clock::now() +
                            std::chrono::seconds(defs::BOOT_STAGE_TIMEOUT_SEC);

  if (safe_mode) {
    std::cerr << "[module] safe mode, skip common post-fs-data.d scripts"
              << std::endl;
  } else {
    exec_common_scripts("post-fs-data.d", wait, deadline);
  }

  if (safe_mode) {
    std::cerr << "[module] safe mode, disable all modules" << std::endl;
    disable_all_modules();
    return 0;
  }

  handle_updated_modules();
  prune_modules();

  if (!regenerate_preinit_rc())
    std::cerr << "[module] regenerate preinit rc failed" << std::endl;

  // Module SELinux rules must be live before any module script runs.
  load_sepolicy_rule();

  metamodule_exec_stage_script("post-fs-data", wait, deadline);
  exec_stage_script("post-fs-data", wait, deadline);

  load_system_prop();

  metamodule_exec_mount_script();
  run_stage_internal("post-mount", wait, deadline);

  ::chdir("/");
  return 0;
}

int on_services() {
  std::cout << "[module] on_services triggered" << std::endl;
  run_stage_internal("service", ScriptWait::NoWait,
                     std::chrono::steady_clock::now());
  return 0;
}

int on_boot_completed() {
  std::cout << "[module] on_boot_completed triggered" << std::endl;
  run_stage_internal("boot-completed", ScriptWait::NoWait,
                     std::chrono::steady_clock::now());
  return 0;
}

int run_stage(const std::string &stage) {
  run_stage_internal(stage, ScriptWait::NoWait,
                     std::chrono::steady_clock::now());
  return 0;
}

// ---------------------------------------------------------------------------
// Module lifecycle
// ---------------------------------------------------------------------------

void handle_updated_modules() {
  foreach_module(ModuleType::Updated, [](const std::string &updated) {
    if (!utils::is_dir(updated))
      return;

    const std::string name = utils::base_name(updated);
    if (!validate_module_id(name))
      return;

    const std::string target = utils::join(defs::module_dir(), name);
    bool disabled = false;
    bool removed = false;
    if (utils::exists(target)) {
      // A disabled/removed update must stay disabled/removed after the swap.
      disabled = utils::exists(utils::join(target, defs::DISABLE_FILE_NAME));
      removed = utils::exists(utils::join(target, defs::REMOVE_FILE_NAME));
      utils::remove_dir_all(target);
    }

    utils::ensure_dir_exists(defs::module_dir());
    if (!utils::rename_path(updated, target)) {
      std::cerr << "[module] failed to move " << updated << " -> " << target
                << std::endl;
      return;
    }

    if (removed)
      utils::ensure_file_exists(utils::join(target, defs::REMOVE_FILE_NAME));
    else if (disabled)
      utils::ensure_file_exists(utils::join(target, defs::DISABLE_FILE_NAME));
  });
}

void prune_modules() {
  foreach_module(ModuleType::All, [](const std::string &module) {
    if (!utils::exists(utils::join(module, defs::REMOVE_FILE_NAME)))
      return;

    std::cout << "[module] remove module: " << module << std::endl;

    const std::string id = utils::base_name(module);
    Properties props;
    const bool is_meta = read_module_prop(module, props) && is_metamodule(props);

    if (is_meta) {
      // Removing the metamodule itself: drop its symlink first.
      metamodule_remove_symlink();
    } else {
      // Let an active metamodule react to the removal of a regular module.
      metamodule_exec_metauninstall_script(id);
    }

    // Run the module's own uninstaller before deleting the directory.
    const std::string uninstaller = utils::join(module, "uninstall.sh");
    if (utils::is_file(uninstaller))
      exec_script(uninstaller, ScriptWait::Forever,
                  std::chrono::steady_clock::now());

    if (!utils::remove_dir_all(module))
      std::cerr << "[module] failed to remove " << module << std::endl;
  });
}

void disable_all_modules() {
  mark_all_modules(defs::DISABLE_FILE_NAME);
  regenerate_preinit_rc();
}

void load_system_prop() {
  foreach_module(ModuleType::Active, [](const std::string &module) {
    const std::string prop = utils::join(module, "system.prop");
    if (!utils::is_file(prop))
      return;

    std::string content;
    if (!utils::read_file(prop, content))
      return;

    std::istringstream stream(content);
    std::string line;
    while (std::getline(stream, line)) {
      const std::string trimmed = utils::trim(line);
      if (trimmed.empty() || trimmed[0] == '#')
        continue;
      const size_t eq = trimmed.find('=');
      if (eq == std::string::npos)
        continue;
      const std::string key = utils::trim(trimmed.substr(0, eq));
      const std::string value = utils::trim(trimmed.substr(eq + 1));
      if (!key.empty())
        utils::setprop(key, value);
    }
  });
}

bool regenerate_preinit_rc() {
  const std::string dir = preinit_dir();
  if (!utils::ensure_dir_exists(dir))
    return false;

  const std::string tmp = utils::join(dir, defs::MODULES_RC_TMP_FILE);
  const std::string out_path = utils::join(dir, defs::MODULES_RC_FILE);

  std::string output;
  // Common initrc.d scripts first.
  collect_rc_files(utils::join(defs::adb_dir(), "initrc.d"), "", output);

  // modules_update/ is collected first so freshly installed modules win on ID
  // collisions. An empty value marks a disabled/removed module.
  std::map<std::string, std::string> modules;
  const std::string sources[] = {defs::module_update_dir(), defs::module_dir()};
  for (const auto &source : sources) {
    if (!utils::is_dir(source))
      continue;
    for (const auto &name : utils::list_dir(source)) {
      const std::string module_path = utils::join(source, name);
      if (!utils::is_dir(module_path))
        continue;

      if (utils::exists(utils::join(module_path, defs::DISABLE_FILE_NAME)) ||
          utils::exists(utils::join(module_path, defs::REMOVE_FILE_NAME))) {
        modules.insert({name, std::string()});
        continue;
      }
      modules.emplace(name, module_path);
    }
  }

  for (const auto &entry : modules) {
    if (entry.second.empty())
      continue;
    collect_rc_files(utils::join(entry.second, defs::MODULE_INIT_RC_DIR),
                     entry.first, output);
  }

  if (!utils::write_file(tmp, output))
    return false;
  if (!utils::rename_path(tmp, out_path))
    return false;

  // Clear the stale file at the other candidate path.
  const std::string stale_dir =
      dir == defs::preinit_dir_watchdog() ? defs::preinit_dir_default()
                                          : defs::preinit_dir_watchdog();
  ::unlink(utils::join(stale_dir, defs::MODULES_RC_FILE).c_str());
  return true;
}

// ---------------------------------------------------------------------------
// Management commands
// ---------------------------------------------------------------------------

static int require_module(const std::string &id, std::string &path) {
  if (!validate_module_id(id)) {
    std::cerr << "[module] invalid module id: " << id << std::endl;
    return -1;
  }
  path = utils::join(defs::module_dir(), id);
  if (!utils::is_dir(path)) {
    std::cerr << "[module] module not found: " << id << std::endl;
    return -1;
  }
  return 0;
}

int enable_module(const std::string &id) {
  std::string path;
  if (require_module(id, path) != 0)
    return 1;

  const std::string disable = utils::join(path, defs::DISABLE_FILE_NAME);
  if (utils::exists(disable))
    ::unlink(disable.c_str());

  regenerate_preinit_rc();
  std::cout << "[module] module " << id << " enabled" << std::endl;
  return 0;
}

int disable_module(const std::string &id) {
  std::string path;
  if (require_module(id, path) != 0)
    return 1;

  utils::ensure_file_exists(utils::join(path, defs::DISABLE_FILE_NAME));
  regenerate_preinit_rc();
  std::cout << "[module] module " << id << " disabled" << std::endl;
  return 0;
}

int uninstall_module(const std::string &id) {
  std::string path;
  if (require_module(id, path) != 0)
    return 1;

  utils::ensure_file_exists(utils::join(path, defs::REMOVE_FILE_NAME));
  regenerate_preinit_rc();
  std::cout << "[module] module " << id << " marked for removal" << std::endl;
  return 0;
}

int undo_uninstall_module(const std::string &id) {
  std::string path;
  if (require_module(id, path) != 0)
    return 1;

  const std::string remove = utils::join(path, defs::REMOVE_FILE_NAME);
  if (utils::exists(remove))
    ::unlink(remove.c_str());

  regenerate_preinit_rc();
  std::cout << "[module] removal mark removed for " << id << std::endl;
  return 0;
}

int run_action(const std::string &id) {
  std::string path;
  if (require_module(id, path) != 0)
    return 1;

  const std::string script = utils::join(path, defs::MODULE_ACTION_SH);
  if (!utils::is_file(script)) {
    std::cerr << "[module] " << id << " has no action.sh" << std::endl;
    return 1;
  }

  // Propagate the script's exit status so callers can tell success from
  // failure (e.g. the manager's action UI).
  int exit_code = 0;
  exec_script(script, ScriptWait::Forever, std::chrono::steady_clock::now(), {},
              &exit_code);
  return exit_code;
}

namespace {

// Append @value as a JSON string literal, escaping the characters the JSON
// grammar requires. Mirrors the escaping the kernel used to do.
void append_json_string(std::string &out, const std::string &value) {
  out.push_back('"');
  for (unsigned char c : value) {
    switch (c) {
    case '"':
      out += "\\\"";
      break;
    case '\\':
      out += "\\\\";
      break;
    case '\n':
      out += "\\n";
      break;
    case '\r':
      out += "\\r";
      break;
    case '\t':
      out += "\\t";
      break;
    default:
      if (c < 0x20) {
        char esc[7];
        std::snprintf(esc, sizeof(esc), "\\u%04x", c);
        out += esc;
      } else {
        out.push_back(static_cast<char>(c));
      }
    }
  }
  out.push_back('"');
}

} // namespace

int list_modules_json() {
  const std::string root = utils::strip_trailing_slash(defs::module_dir());

  std::string out = "[";
  bool first = true;

  if (utils::is_dir(root)) {
    for (const auto &name : utils::list_dir(root)) {
      const std::string path = utils::join(root, name);
      if (!utils::is_dir(path))
        continue;

      Properties props;
      read_module_prop(path, props);

      std::string id = prop_get(props, "id");
      if (id.empty())
        id = name;

      const bool enabled =
          !utils::exists(utils::join(path, defs::DISABLE_FILE_NAME));
      const bool removed =
          utils::exists(utils::join(path, defs::REMOVE_FILE_NAME));
      const bool update =
          utils::exists(utils::join(path, defs::UPDATE_FILE_NAME));
      const bool skip_mount = utils::exists(utils::join(path, "skip_mount"));
      const bool has_system = utils::is_dir(utils::join(path, "system"));
      const bool has_action =
          utils::is_file(utils::join(path, defs::MODULE_ACTION_SH));
      const bool has_webui = utils::is_dir(utils::join(path, defs::MODULE_WEB_DIR));

      std::string object = "{";
      auto add_str = [&object](const char *key, const std::string &value) {
        object += '"';
        object += key;
        object += "\":";
        append_json_string(object, value);
        object.push_back(',');
      };
      auto add_bool = [&object](const char *key, bool value) {
        object += '"';
        object += key;
        object += "\":";
        object += value ? "true" : "false";
        object.push_back(',');
      };

      add_str("id", id);
      add_str("name", prop_get(props, "name"));
      add_str("version", prop_get(props, "version"));
      add_str("versionCode", prop_get(props, "versionCode"));
      add_str("author", prop_get(props, "author"));
      add_str("description", prop_get(props, "description"));
      add_bool("enabled", enabled);
      add_bool("metamodule", is_metamodule(props));
      add_bool("update", update);
      add_bool("remove", removed);
      add_bool("skipMount", skip_mount);
      add_bool("hasSystem", has_system);
      add_bool("hasActionScript", has_action);
      add_bool("hasWebUi", has_webui);
      object.back() = '}'; // drop the trailing comma

      if (!first)
        out.push_back(',');
      first = false;
      out += object;
    }
  }

  out += "]\n";
  std::cout << out;
  return 0;
}

int list_modules() {
  const std::string root = utils::strip_trailing_slash(defs::module_dir());
  if (!utils::is_dir(root)) {
    std::cout << "no modules installed" << std::endl;
    return 0;
  }

  for (const auto &name : utils::list_dir(root)) {
    const std::string path = utils::join(root, name);
    if (!utils::is_dir(path) ||
        !utils::is_file(utils::join(path, defs::MODULE_PROP)))
      continue;

    Properties props;
    read_module_prop(path, props);

    std::string id = prop_get(props, "id");
    if (id.empty())
      id = name;

    const bool enabled =
        !utils::exists(utils::join(path, defs::DISABLE_FILE_NAME));
    const bool removed =
        utils::exists(utils::join(path, defs::REMOVE_FILE_NAME));
    const bool update =
        utils::exists(utils::join(path, defs::UPDATE_FILE_NAME));
    const bool has_action =
        utils::is_file(utils::join(path, defs::MODULE_ACTION_SH));

    std::cout << id << ":\n"
              << "  name: " << prop_get(props, "name") << "\n"
              << "  version: " << prop_get(props, "version") << "\n"
              << "  author: " << prop_get(props, "author") << "\n"
              << "  description: " << prop_get(props, "description") << "\n"
              << "  enabled: " << (enabled ? "true" : "false") << "\n"
              << "  remove: " << (removed ? "true" : "false") << "\n"
              << "  update: " << (update ? "true" : "false") << "\n"
              << "  action: " << (has_action ? "true" : "false") << "\n";
  }
  return 0;
}

int refresh_initrc() {
  if (!regenerate_preinit_rc()) {
    std::cerr << "[module] regenerate preinit rc failed" << std::endl;
    return 1;
  }
  return 0;
}

int install() {
  const std::string target = defs::boot_path();
  const std::string dir = utils::dir_name(target);

  if (!utils::ensure_dir_exists(dir)) {
    std::cerr << "[module] cannot create " << dir << std::endl;
    return 1;
  }

  // Copy through /proc/self/exe rather than its resolved path: this is the
  // running ncore (the APK's libncore.so), and it stays valid even when the
  // destination is the same file, mirroring KernelSU's `ksud install`.
  const int in = ::open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
  if (in < 0) {
    std::cerr << "[module] open /proc/self/exe failed: "
              << std::strerror(errno) << std::endl;
    return 1;
  }

  const int out = ::open(target.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                         0755);
  if (out < 0) {
    std::cerr << "[module] open " << target << " failed: "
              << std::strerror(errno) << std::endl;
    ::close(in);
    return 1;
  }

  char buf[65536];
  for (;;) {
    const ssize_t r = ::read(in, buf, sizeof(buf));
    if (r == 0)
      break;
    if (r < 0) {
      if (errno == EINTR)
        continue;
      std::cerr << "[module] read failed: " << std::strerror(errno) << std::endl;
      ::close(in);
      ::close(out);
      return 1;
    }
    ssize_t off = 0;
    while (off < r) {
      const ssize_t w = ::write(out, buf + off, static_cast<size_t>(r - off));
      if (w < 0) {
        if (errno == EINTR)
          continue;
        std::cerr << "[module] write failed: " << std::strerror(errno)
                  << std::endl;
        ::close(in);
        ::close(out);
        return 1;
      }
      off += w;
    }
  }
  ::close(in);
  ::close(out);

  if (::chmod(target.c_str(), 0755) != 0)
    std::cerr << "[module] chmod failed: " << std::strerror(errno) << std::endl;

  // Best effort SELinux label so init can exec it. nksu's domain is
  // unconfined, so a failure here is cosmetic.
  const char con[] = "u:object_r:system_file:s0";
  ::setxattr(target.c_str(), "security.selinux", con, sizeof(con) - 1, 0);

  std::cout << "[module] installed " << target << std::endl;
  return 0;
}

// ---------------------------------------------------------------------------
// Module installation
//
// Ported from ksud's `install_module` (userspace/ksud/src/module.rs) and the
// parts of userspace/ksud/src/installer.sh that a module's customize.sh relies
// on. Unlike ksud, extraction is done natively with ZipArchive instead of
// shelling out to `unzip`, so ncore does not need a bundled busybox.
// ---------------------------------------------------------------------------

namespace {

constexpr const char *SYSTEM_CON = "u:object_r:system_file:s0";

// Helper functions and the default install_module(). This is the subset of
// installer.sh that modules depend on; the archive has already been extracted
// into $MODPATH by the time this runs.
constexpr const char *kInstallerPrelude = R"NCORE(
ui_print() { echo "$1"; }

abort() {
  ui_print "! $1"
  [ -n "$MODPATH" ] && rm -rf "$MODPATH" 2>/dev/null
  rm -rf "$TMPDIR" 2>/dev/null
  exit 1
}

toupper() { echo "$@" | tr '[:lower:]' '[:upper:]'; }

print_title() {
  local line1len line2len len bar
  line1len=$(echo -n "$1" | wc -c)
  line2len=$(echo -n "$2" | wc -c)
  len=$line2len
  [ "$line1len" -gt "$line2len" ] && len=$line1len
  len=$((len + 2))
  bar=$(printf "%${len}s" | tr ' ' '*')
  ui_print "$bar"
  ui_print " $1 "
  [ -n "$2" ] && ui_print " $2 "
  ui_print "$bar"
}

is_mounted() {
  grep -q " $(readlink -f "$1") " /proc/mounts 2>/dev/null
  return $?
}

check_sepolicy() { return 0; }

set_perm() {
  chown "$2:$3" "$1" || return 1
  chmod "$4" "$1" || return 1
  local CON="$5"
  [ -z "$CON" ] && CON=u:object_r:system_file:s0
  chcon "$CON" "$1" || return 1
}

set_perm_recursive() {
  find "$1" -type d 2>/dev/null | while read -r dir; do
    set_perm "$dir" "$2" "$3" "$4" "$6"
  done
  find "$1" \( -type f -o -type l \) 2>/dev/null | while read -r file; do
    set_perm "$file" "$2" "$3" "$5" "$6"
  done
}

mktouch() {
  mkdir -p "${1%/*}" 2>/dev/null
  [ -z "$2" ] && touch "$1" || echo "$2" > "$1"
  chmod 644 "$1"
}

mark_remove() {
  mkdir -p "${1%/*}" 2>/dev/null
  mknod "$1" c 0 0
  chmod 644 "$1"
}

mark_replace() {
  rm -rf "$1" 2>/dev/null
  mkdir -p "$1" 2>/dev/null
  mknod "$1/.replace" c 0 0
  chmod 644 "$1/.replace"
}

api_level_arch_detect() {
  API=$(getprop ro.build.version.sdk)
  ABI=$(getprop ro.product.cpu.abi)
  case "$ABI" in
    x86) ARCH=x86; ABI32=x86; IS64BIT=false ;;
    arm64-v8a) ARCH=arm64; ABI32=armeabi-v7a; IS64BIT=true ;;
    x86_64) ARCH=x64; ABI32=x86; IS64BIT=true ;;
    riscv64) ARCH=riscv64; ABI32=; IS64BIT=true ;;
    *) ARCH=arm; ABI=armeabi-v7a; ABI32=armeabi-v7a; IS64BIT=false ;;
  esac
}

handle_partition() {
  if [ ! -e "$MODPATH/system/$1" ]; then
    return 0
  fi
  if [ -d "/$1" ] && [ ! -L "/$1" ]; then
    ui_print "- Handle partition /$1"
    mv -f "$MODPATH/system/$1" "$MODPATH/$1" && ln -sf "../$1" "$MODPATH/system/$1"
  fi
}

install_module() {
  if [ -f "$MODPATH/install.sh" ] && [ ! -f "$MODPATH/customize.sh" ]; then
    . "$MODPATH/install.sh"
    command -v print_modname >/dev/null 2>&1 && print_modname
    command -v on_install >/dev/null 2>&1 && on_install
  elif [ -f "$MODPATH/customize.sh" ]; then
    . "$MODPATH/customize.sh"
  fi

  for TARGET in $REPLACE; do
    ui_print "- Replace target: $TARGET"
    mark_replace "$MODPATH$TARGET"
  done
  for TARGET in $REMOVE; do
    ui_print "- Remove target: $TARGET"
    mark_remove "$MODPATH$TARGET"
  done

  handle_partition vendor
  handle_partition system_ext
  handle_partition product
  handle_partition odm
}
)NCORE";

bool boot_completed() {
  const char *forced = ::getenv("NCORE_ASSUME_BOOT_COMPLETED");
  if (forced != nullptr && *forced != '\0' && std::strcmp(forced, "0") != 0)
    return true;
  return utils::getprop("sys.boot_completed") == "1";
}

std::string format_size(uint64_t bytes) {
  char buffer[32];
  std::snprintf(buffer, sizeof(buffer), "%.1f MiB",
                static_cast<double>(bytes) / (1024.0 * 1024.0));
  return buffer;
}

std::string shell_quote(const std::string &value) {
  std::string out = "'";
  for (char c : value) {
    if (c == '\'')
      out += "'\\''";
    else
      out.push_back(c);
  }
  out.push_back('\'');
  return out;
}

void set_selinux_context(const std::string &path, const std::string &context) {
  // Best effort: ncore runs in an unconfined domain, so a failure is cosmetic.
  ::lsetxattr(path.c_str(), "security.selinux", context.c_str(), context.size(),
              0);
}

void restore_syscon(const std::string &path) {
  if (!utils::exists(path))
    return;
  set_selinux_context(path, SYSTEM_CON);
  if (utils::is_dir(path) && !utils::is_symlink(path)) {
    for (const auto &name : utils::list_dir(path))
      restore_syscon(utils::join(path, name));
  }
}

bool remove_entry(const std::string &path) {
  if (utils::is_dir(path) && !utils::is_symlink(path))
    return utils::remove_dir_all(path);
  if (::unlink(path.c_str()) == 0)
    return true;
  return errno == ENOENT;
}

bool write_script(const std::string &path, const std::string &content) {
  return utils::write_file(path, content) && ::chmod(path.c_str(), 0755) == 0;
}

bool copy_file(const std::string &from, const std::string &to) {
  std::string data;
  return utils::read_file(from, data) && utils::write_file(to, data);
}

// The legacy ARCH/ABI values installer.sh derives at runtime.
struct ArchInfo {
  std::string arch;
  std::string abi;
  std::string abi32;
  bool is64 = false;
};

ArchInfo detect_arch() {
  const std::string abi = utils::getprop("ro.product.cpu.abi");
  if (abi == "x86")
    return {"x86", "x86", "x86", false};
  if (abi == "arm64-v8a")
    return {"arm64", abi, "armeabi-v7a", true};
  if (abi == "x86_64")
    return {"x64", abi, "x86", true};
  if (abi == "riscv64")
    return {"riscv64", abi, "", true};
  return {"arm", "armeabi-v7a", "armeabi-v7a", false};
}

std::string build_installer_script(const std::string &module_path,
                                   const std::string &zip_real,
                                   const std::string &tmp_dir,
                                   const std::string &id,
                                   const Properties &props,
                                   const std::string &metainstall) {
  const ArchInfo arch = detect_arch();
  const std::string nvbase = utils::strip_trailing_slash(defs::adb_dir());

  std::ostringstream out;
  out << "umask 022\n";
  out << "BOOTMODE=true\n";
  out << "NVBASE=" << shell_quote(nvbase) << "\n";
  out << "MODDIRNAME=modules_update\n";
  out << "MODULEROOT=" << shell_quote(utils::join(nvbase, "modules_update"))
      << "\n";
  out << "MODPATH=" << shell_quote(module_path) << "\n";
  out << "TMPDIR=" << shell_quote(tmp_dir) << "\n";
  out << "ZIPFILE=" << shell_quote(zip_real) << "\n";
  out << "MODID=" << shell_quote(id) << "\n";
  out << "MODNAME=" << shell_quote(prop_get(props, "name")) << "\n";
  out << "MODAUTH=" << shell_quote(prop_get(props, "author")) << "\n";
  out << "MAGISK_VER=25.2\n";
  out << "MAGISK_VER_CODE=25200\n";
  out << "API=" << shell_quote(utils::getprop("ro.build.version.sdk")) << "\n";
  out << "ABI=" << shell_quote(arch.abi) << "\n";
  out << "ABI32=" << shell_quote(arch.abi32) << "\n";
  out << "ARCH=" << shell_quote(arch.arch) << "\n";
  out << "IS64BIT=" << (arch.is64 ? "true" : "false") << "\n";
  out << "export BOOTMODE NVBASE MODDIRNAME MODULEROOT MODPATH TMPDIR ZIPFILE\n";
  out << "export MODID MODNAME MODAUTH MAGISK_VER MAGISK_VER_CODE\n";
  out << "export API ABI ABI32 ARCH IS64BIT\n";
  out << kInstallerPrelude;
  if (!metainstall.empty())
    out << "\n" << metainstall << "\n";
  out << "\ninstall_module\n";
  return out.str();
}

} // namespace

int install_module(const std::string &zip) {
  if (!boot_completed()) {
    std::cerr << "[module] Android is still booting, refusing to install"
              << std::endl;
    return 1;
  }

  const std::string zip_real = utils::realpath_str(zip);
  if (zip_real.empty() || !utils::is_file(zip_real)) {
    std::cerr << "[module] package not found: " << zip << std::endl;
    return 1;
  }

  ZipArchive archive;
  std::string error;
  if (!archive.open(zip_real, &error)) {
    std::cerr << "[module] invalid module package: " << error << std::endl;
    return 1;
  }

  std::string prop_content;
  if (!archive.read("module.prop", prop_content, &error)) {
    std::cerr << "[module] " << error << std::endl;
    return 1;
  }

  Properties props;
  parse_properties(prop_content, props);

  const std::string id = utils::trim(prop_get(props, "id"));
  if (!validate_module_id(id)) {
    std::cerr << "[module] invalid module id in module.prop: '" << id << "'"
              << std::endl;
    return 1;
  }

  const bool is_meta = is_metamodule(props);

  if (!is_meta) {
    bool disabled = false;
    if (!metamodule_check_install_safety(&disabled)) {
      std::cout << "\n- Installation blocked: a metamodule with a custom "
                   "installer is active"
                << std::endl;
      std::cout << (disabled
                        ? "- Current state: disabled; re-enable or uninstall it "
                          "and reboot"
                        : "- Current state: pending changes; reboot first")
                << std::endl;
      return 1;
    }
  } else {
    const std::string existing = get_metamodule_id();
    if (!existing.empty() && existing != id) {
      std::cerr << "[module] cannot install metamodule " << id
                << ": metamodule " << existing << " is already installed"
                << std::endl;
      return 1;
    }
  }

  const std::string updated_dir = utils::join(defs::module_update_dir(), id);

  std::cout << "- Module size: " << format_size(archive.uncompressed_size())
            << std::endl;
  std::cout << "- Installing to " << updated_dir << std::endl;

  if (!utils::ensure_dir_exists(defs::module_update_dir())) {
    std::cerr << "[module] failed to create " << defs::module_update_dir()
              << std::endl;
    return 1;
  }
  set_selinux_context(utils::strip_trailing_slash(defs::module_update_dir()),
                      SYSTEM_CON);

  if (!utils::ensure_clean_dir(updated_dir)) {
    std::cerr << "[module] failed to prepare " << updated_dir << std::endl;
    return 1;
  }

  std::cout << "- Extracting module files" << std::endl;
  if (!archive.extract_all(updated_dir, &error)) {
    std::cerr << "[module] extraction failed: " << error << std::endl;
    utils::remove_dir_all(updated_dir);
    return 1;
  }

  const std::string module_system = utils::join(updated_dir, "system");
  if (utils::is_dir(module_system)) {
    ::chmod(module_system.c_str(), 0755);
    restore_syscon(module_system);
  }

  // A metamodule may override the default installer with metainstall.sh. A
  // disabled metamodule is ignored, matching ksud.
  std::string metainstall;
  if (!is_meta) {
    const std::string meta_path = get_metamodule_path();
    if (!meta_path.empty() &&
        !utils::exists(utils::join(meta_path, defs::DISABLE_FILE_NAME))) {
      utils::read_file(utils::join(meta_path, defs::METAMODULE_METAINSTALL_SCRIPT),
                       metainstall);
    }
  }

  const std::string tmp_dir =
      utils::join(utils::strip_trailing_slash(defs::working_dir()), "tmp");
  utils::ensure_clean_dir(tmp_dir);
  const std::string script_path = utils::join(tmp_dir, "installer.sh");
  if (!write_script(script_path,
                    build_installer_script(updated_dir, zip_real, tmp_dir, id,
                                           props, metainstall))) {
    std::cerr << "[module] failed to write installer script" << std::endl;
    utils::remove_dir_all(updated_dir);
    return 1;
  }

  std::cout << "- Running module installer" << std::endl;
  int exit_code = 0;
  exec_script(script_path, ScriptWait::Forever, std::chrono::steady_clock::now(),
              {{"KSU_MODULE", id}, {"BOOTMODE", "true"}}, &exit_code);
  utils::remove_dir_all(tmp_dir);

  if (exit_code != 0) {
    std::cerr << "[module] installer failed with status " << exit_code
              << std::endl;
    utils::remove_dir_all(updated_dir);
    return 1;
  }

  // Cleanup that installer.sh performs after a successful install.
  remove_entry(utils::join(updated_dir, "customize.sh"));
  remove_entry(utils::join(updated_dir, "system/placeholder"));
  remove_entry(utils::join(updated_dir, "README.md"));
  for (const auto &name : utils::list_dir(updated_dir)) {
    if (name.compare(0, 4, ".git") == 0)
      remove_entry(utils::join(updated_dir, name));
  }

  // Stage the module for activation: write module.prop and the update flag into
  // modules/<id>, and drop any stale disable/remove marks.
  const std::string module = utils::join(defs::module_dir(), id);
  if (!utils::ensure_dir_exists(module)) {
    std::cerr << "[module] failed to create " << module << std::endl;
    utils::remove_dir_all(updated_dir);
    return 1;
  }
  if (!copy_file(utils::join(updated_dir, defs::MODULE_PROP),
                 utils::join(module, defs::MODULE_PROP))) {
    std::cerr << "[module] failed to stage module.prop" << std::endl;
    return 1;
  }
  utils::ensure_file_exists(utils::join(module, defs::UPDATE_FILE_NAME));
  remove_entry(utils::join(module, defs::REMOVE_FILE_NAME));
  remove_entry(utils::join(module, defs::DISABLE_FILE_NAME));
  set_selinux_context(module, SYSTEM_CON);
  set_selinux_context(utils::join(module, defs::MODULE_PROP), SYSTEM_CON);

  if (is_meta && !metamodule_ensure_symlink(module))
    std::cerr << "[module] metamodule symlink could not be created" << std::endl;

  if (!regenerate_preinit_rc())
    std::cerr << "[module] regenerate preinit rc failed" << std::endl;

  std::cout << "- Module installed successfully!" << std::endl;
  return 0;
}

} // namespace modules
