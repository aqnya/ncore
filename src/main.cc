#include "cli.hpp"
#include "su/su.hpp"

#include <cstring>

int main(int argc, char **argv) {
  // The kernel redirects an execve() of /system/bin/su to this binary, keeping
  // argv[0] intact, so detect the `su` invocation by argv[0] (or the explicit
  // `ncore su` subcommand).
  if (su::is_su_invocation(argc > 0 ? argv[0] : nullptr))
    return su::run(argc, argv);

  if (argc > 1 && std::strcmp(argv[1], "su") == 0)
    return su::run(argc - 1, argv + 1);

  cli::arguments args;
  const int rc = cli::parse_cli(argc, argv, args);
  if (rc != 0)
    return rc;

  return 0;
}
