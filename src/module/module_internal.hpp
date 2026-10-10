#pragma once

#include "module/module.hpp"

#include <chrono>
#include <functional>
#include <string>
#include <utility>
#include <vector>

// Internal definitions shared by the module runtime translation units. Layout
// and behaviour mirror KernelSU's userspace/ksud/src/defs.rs so that existing
// KernelSU modules keep working unchanged.
namespace modules {

namespace defs {

// Fixed KernelSU-compatible file names.
constexpr const char *MODULE_PROP = "module.prop";
constexpr const char *MODULE_WEB_DIR = "webroot";
constexpr const char *MODULE_ACTION_SH = "action.sh";
constexpr const char *MODULE_INIT_RC_DIR = "initrc";

constexpr const char *DISABLE_FILE_NAME = "disable";
constexpr const char *UPDATE_FILE_NAME = "update";
constexpr const char *REMOVE_FILE_NAME = "remove";

constexpr const char *METAMODULE_MOUNT_SCRIPT = "metamount.sh";
constexpr const char *METAMODULE_METAUNINSTALL_SCRIPT = "metauninstall.sh";

constexpr const char *MODULES_RC_FILE = "modules.rc";
constexpr const char *MODULES_RC_TMP_FILE = ".modules.rc.tmp";

constexpr const char *SYSTEM_SH_PATH = "/system/bin/sh";

// Default layout, identical to KernelSU so existing modules work unchanged.
constexpr const char *DEFAULT_ADB_DIR = "/data/adb/";
constexpr const char *DEFAULT_WORKING_DIR = "/data/adb/ksu/";
constexpr const char *DEFAULT_PREINIT_DIR_WATCHDOG = "/metadata/watchdog/ksu/";
constexpr const char *DEFAULT_PREINIT_DIR_DEFAULT = "/metadata/ksu/";

// Same shared deadline ksud uses for the post-fs-data stage.
constexpr int BOOT_STAGE_TIMEOUT_SEC = 35;

// KernelSU exposes these to module scripts. ncore keeps the KSU_* names so
// modules written for KernelSU can be reused verbatim.
constexpr const char *KSU_VERSION_NAME = "ncore";
constexpr const char *KSU_VERSION_CODE = "0";
constexpr const char *KSU_UAPI_VERSION = "0";
constexpr const char *KSU_RUNTIME_MODE = "0";

// Base directories. These default to the KernelSU layout but can be
// overridden through NCORE_ADB_DIR / NCORE_WORKING_DIR, which is useful for
// tests and for ports that use a different data directory.
const std::string &adb_dir();
const std::string &working_dir();
const std::string &binary_dir();
const std::string &log_dir();
const std::string &module_dir();
const std::string &module_update_dir();
const std::string &metamodule_dir();
const std::string &busybox_path();
const std::string &preinit_dir_watchdog();
const std::string &preinit_dir_default();

// Where the kernel execs ncore from at boot (init.rc). The daemon copies
// /proc/self/exe here; the host can override it with NCORE_BOOT_PATH.
const std::string &boot_path();

} // namespace defs

namespace utils {

std::string getprop(const std::string &name);
bool setprop(const std::string &name, const std::string &value);

bool is_safe_mode();
bool has_magisk();
std::string which(const std::string &name);

void umask0();
void switch_cgroups();
void detach_process_group(bool use_init_pgrp);

bool exists(const std::string &path);
bool is_dir(const std::string &path);
bool is_file(const std::string &path);
bool is_symlink(const std::string &path);
bool is_executable(const std::string &path);

bool ensure_dir_exists(const std::string &dir);
bool ensure_file_exists(const std::string &file);
bool ensure_clean_dir(const std::string &dir);

bool read_file(const std::string &path, std::string &out);
bool write_file(const std::string &path, const std::string &data,
                bool append = false);

bool remove_dir_all(const std::string &path);
bool rename_path(const std::string &from, const std::string &to);
bool read_link(const std::string &path, std::string &out);

std::vector<std::string> list_dir(const std::string &dir);

std::string base_name(const std::string &path);
std::string dir_name(const std::string &path);
std::string join(const std::string &dir, const std::string &name);
std::string strip_trailing_slash(const std::string &path);
std::string realpath_str(const std::string &path);
std::string trim(const std::string &value);

} // namespace utils

enum class ModuleType { All, Active, Updated };

// Same wait policy as ksud's ScriptWait.
enum class ScriptWait { NoWait, Forever, Until };

using Deadline = std::chrono::steady_clock::time_point;
using ModuleVisitor = std::function<void(const std::string &path)>;
using Properties = std::vector<std::pair<std::string, std::string>>;

void foreach_module(ModuleType type, const ModuleVisitor &visitor);

bool read_module_prop(const std::string &module_path, Properties &out);
std::string prop_get(const Properties &props, const std::string &key);

bool validate_module_id(const std::string &id);

// Script execution. `extra_env` entries override the common environment and
// are used by the metamodule scripts (MODULE_DIR / MODULE_ID). When
// `exit_code` is non-null it receives the script's exit status (128 + signal
// when killed, -1 when the script could not be run).
void exec_script(const std::string &path, ScriptWait wait,
                 const Deadline &deadline,
                 const std::vector<std::pair<std::string, std::string>>
                     &extra_env = {},
                 int *exit_code = nullptr);
void exec_stage_script(const std::string &stage, ScriptWait wait,
                       const Deadline &deadline);
void exec_common_scripts(const std::string &dir, ScriptWait wait,
                         const Deadline &deadline);

// Metamodule support.
bool is_metamodule(const Properties &props);
std::string get_metamodule_path();
std::string get_metamodule_id();
void metamodule_exec_stage_script(const std::string &stage, ScriptWait wait,
                                  const Deadline &deadline);
void metamodule_exec_mount_script();
void metamodule_remove_symlink();

// Module lifecycle, mirroring ksud's module.rs.
void handle_updated_modules();
void prune_modules();
void disable_all_modules();
void load_system_prop();
bool regenerate_preinit_rc();

// Push every active module's sepolicy.rule to the kernel (parsed into the
// KernelSU batch format and sent through the nksu control fd). Missing rule
// files are skipped.
void load_sepolicy_rule();

} // namespace modules
