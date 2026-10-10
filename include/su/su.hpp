#pragma once

// `su` for nksu.
//
// The kernel redirects an execve() of /system/bin/su to this binary and has
// already escalated the process to root in the nksu domain by the time we run,
// so this only has to interpret the su arguments and exec the shell.  It
// mirrors the parts of KernelSU's ksud `su`/`root_shell` that programs such as
// tsu and Termux's sudo rely on.
namespace su {

// True when the program was invoked as `su` (argv[0]'s basename is "su").
bool is_su_invocation(const char *arg0);

// Run the `su` command. Returns the process exit code (only on failure; on
// success it does not return because it execs the shell).
int run(int argc, char *argv[]);

} // namespace su
