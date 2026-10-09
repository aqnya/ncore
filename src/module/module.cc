#include "module_internal.hpp"

#include <cerrno>
#include <chrono>
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

// Resolve the script interpreter. KernelSU always uses its bundled busybox, but
// ncore may not ship one, so fall back to busybox on PATH and finally to the
// system shell.
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

bool wait_forever(pid_t pid) {
  int status = 0;
  while (::waitpid(pid, &status, 0) < 0) {
    if (errno != EINTR)
      return false;
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

std::string preinit_ksu_dir() {
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
    const std::vector<std::pair<std::string, std::string>> &extra_env) {
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
    break;
  case ScriptWait::Forever:
    wait_forever(pid);
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
    }
  }

  // Fallback: scan the module directory for metamodule=1.
  std::string found;
  foreach_module(ModuleType::All, [&found](const std::string &module) {
    if (!found.empty())
      return;
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

void load_sepolicy_rule() {
  const std::string sink = defs::sepolicy_sink();
  if (!utils::exists(sink))
    return;

  const int fd = ::open(sink.c_str(), O_WRONLY | O_CLOEXEC);
  if (fd < 0) {
    std::cerr << "[module] cannot open sepolicy sink " << sink << ": "
              << std::strerror(errno) << std::endl;
    return;
  }

  // The kernel sink reads the rule file itself, so hand it one path per
  // write. Rules must be in place before any module script runs.
  foreach_module(ModuleType::Active, [&](const std::string &module) {
    const std::string rule = utils::join(module, "sepolicy.rule");
    if (!utils::is_file(rule))
      return;

    const std::string line = rule + "\n";
    const ssize_t written = ::write(fd, line.c_str(), line.size());
    if (written < 0) {
      std::cerr << "[module] failed to load " << rule << ": "
                << std::strerror(errno) << std::endl;
    } else {
      std::cout << "[module] load sepolicy.rule: " << rule << std::endl;
    }
  });

  ::close(fd);
}

bool regenerate_preinit_rc() {
  const std::string dir = preinit_ksu_dir();
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

  exec_script(script, ScriptWait::Forever, std::chrono::steady_clock::now());
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

    std::cout << id << ":\n"
              << "  name: " << prop_get(props, "name") << "\n"
              << "  version: " << prop_get(props, "version") << "\n"
              << "  author: " << prop_get(props, "author") << "\n"
              << "  description: " << prop_get(props, "description") << "\n"
              << "  enabled: " << (enabled ? "true" : "false") << "\n"
              << "  remove: " << (removed ? "true" : "false") << "\n"
              << "  update: " << (update ? "true" : "false") << "\n";
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

} // namespace modules
