#include "cli.hpp"

int main(int argc, char **argv) {
  cli::arguments args;
  const int rc = cli::parse_cli(argc, argv, args);
  if (rc != 0)
    return rc;

  return 0;
}