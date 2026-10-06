#pragma once


#include <string>
#include <vector>

namespace cli {

struct arguments {

};

int parse_cli(int argc, char* argv[], arguments& args);

}
