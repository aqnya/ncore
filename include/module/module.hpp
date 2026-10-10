#pragma once

#include <string>

// Userspace module runtime for ncore, ported from KernelSU's ksud
// (userspace/ksud/src/module.rs and init_event.rs).
//
// Modules live in /data/adb/modules/<id> and expose lifecycle scripts
// (post-fs-data.sh, service.sh, boot-completed.sh, ...). Init events trigger
// the matching scripts; common scripts in /data/adb/<stage>.d run before the
// per-module ones.
namespace modules {

// Execute the `post-fs-data` init event. Returns 0 on success.
int on_post_fs_data();

// Execute the `service` init event. Returns 0 on success.
int on_services();

// Execute the `boot-completed` init event. Returns 0 on success.
int on_boot_completed();

// Run a single stage (e.g. "post-fs-data", "service", "boot-completed").
// Convenience wrapper around the internal stage runner. Returns 0 on success.
int run_stage(const std::string &stage);

// Print all installed modules and their metadata. Returns 0 on success.
int list_modules();

// Print all installed modules as a KernelSU-compatible JSON array (the schema
// the manager parses). Returns 0 on success.
int list_modules_json();

// Remove the `disable` flag from module <id>.
int enable_module(const std::string &id);

// Create the `disable` flag for module <id>.
int disable_module(const std::string &id);

// Mark module <id> for removal on the next post-fs-data.
int uninstall_module(const std::string &id);

// Clear the removal mark of module <id>.
int undo_uninstall_module(const std::string &id);

// Execute <id>/action.sh.
int run_action(const std::string &id);

// Rebuild the preinit modules.rc from enabled modules. Returns 0 on success.
int refresh_initrc();

// Copy /proc/self/exe to the boot path (defs::boot_path()) so init.rc can
// exec ncore at boot. Returns 0 on success.
int install();

} // namespace modules
