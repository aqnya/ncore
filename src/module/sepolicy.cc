// ncore -- module sepolicy.rule loader.
//
// Parses KernelSU-style sepolicy.rule files, expands them into the kernel's
// binary sepolicy batch (same wire format as KernelSU's uapi/selinux.h) and
// sends it through the nksu control fd via IOC_SET_SEPOLICY.
//
// The control fd is obtained with prctl(NKSU_PRCTL_GET_DRIVER_FD): the kernel
// installs an anon inode named [fmac_ctl] for root callers.

#include "module_internal.hpp"

#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <iostream>
#include <string>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <vector>

namespace modules {
namespace {

// ---- nksu control interface (mirrors src/include/ioctl.h) -----------------

constexpr int kNksuPrctlGetDriverFd = 204;
constexpr unsigned long kIocMagic = 'F';
constexpr unsigned int kIocSetSepolicy = 12;

struct fmac_ioc {
  uint32_t flag;
  uint32_t size;
  uint8_t data[];
};

#define NKSU_IOC_CMD _IOWR(kIocMagic, 0, struct fmac_ioc)

// ---- batch command ids (mirror src/include/nksu_uapi_selinux.h) -----------

constexpr uint32_t kCmdNormalPerm = 1;
constexpr uint32_t kCmdXperm = 2;
constexpr uint32_t kCmdTypeState = 3;
constexpr uint32_t kCmdType = 4;
constexpr uint32_t kCmdTypeAttr = 5;
constexpr uint32_t kCmdAttr = 6;
constexpr uint32_t kCmdTypeTransition = 7;
constexpr uint32_t kCmdTypeChange = 8;
constexpr uint32_t kCmdGenfscon = 9;
constexpr uint32_t kCmdMany = 0;

constexpr uint32_t kSubAllow = 1;
constexpr uint32_t kSubDeny = 2;
constexpr uint32_t kSubAuditallow = 3;
constexpr uint32_t kSubDontaudit = 4;
constexpr uint32_t kSubXAllow = 1;
constexpr uint32_t kSubXAuditallow = 2;
constexpr uint32_t kSubXDontaudit = 3;
constexpr uint32_t kSubPermissive = 1;
constexpr uint32_t kSubEnforce = 2;
constexpr uint32_t kSubChangeChange = 1;
constexpr uint32_t kSubChangeMember = 2;

struct Atomic {
  uint32_t cmd;
  uint32_t subcmd;
  std::vector<std::string> args; // "*" = wildcard/ALL
};

void encode_object(std::vector<uint8_t> &out, const std::string &obj) {
  const bool wild = obj == "*";
  const uint32_t len = wild ? 0 : static_cast<uint32_t>(obj.size());
  out.insert(out.end(), reinterpret_cast<const uint8_t *>(&len),
             reinterpret_cast<const uint8_t *>(&len) + sizeof(len));
  if (!wild)
    out.insert(out.end(), obj.begin(), obj.end());
  out.push_back(0);
}

void encode_atomic(std::vector<uint8_t> &out, const Atomic &a) {
  out.insert(out.end(), reinterpret_cast<const uint8_t *>(&a.cmd),
             reinterpret_cast<const uint8_t *>(&a.cmd) + sizeof(a.cmd));
  out.insert(out.end(), reinterpret_cast<const uint8_t *>(&a.subcmd),
             reinterpret_cast<const uint8_t *>(&a.subcmd) + sizeof(a.subcmd));
  for (const auto &arg : a.args)
    encode_object(out, arg);
}

// ---- tiny tokenizer/parser ------------------------------------------------

std::vector<std::string> tokenize(const std::string &line) {
  std::vector<std::string> t;
  std::string cur;
  for (char c : line) {
    if (c == '{' || c == '}') {
      if (!cur.empty()) {
        t.push_back(cur);
        cur.clear();
      }
      t.push_back(std::string(1, c));
    } else if (std::isspace(static_cast<unsigned char>(c))) {
      if (!cur.empty()) {
        t.push_back(cur);
        cur.clear();
      }
    } else {
      cur.push_back(c);
    }
  }
  if (!cur.empty())
    t.push_back(cur);
  return t;
}

// Parse one seobject: a word, "*", or "{ word ... }".  Returns false on error.
bool parse_seobj(const std::vector<std::string> &t, size_t &i,
                 std::vector<std::string> &out) {
  out.clear();
  if (i >= t.size())
    return false;
  if (t[i] == "{") {
    i++;
    while (i < t.size() && t[i] != "}")
      out.push_back(t[i++]);
    if (i >= t.size())
      return false;
    i++; // consume '}'
    return !out.empty();
  }
  if (t[i] == "}")
    return false;
  out.push_back(t[i++]);
  return true;
}

bool parse_seobj_single(const std::vector<std::string> &t, size_t &i,
                        std::string &out) {
  if (i >= t.size() || t[i] == "{" || t[i] == "}")
    return false;
  out = t[i++];
  return true;
}

// Append the cross product expansion.
void expand_normal(std::vector<Atomic> &out, uint32_t subcmd,
                   const std::vector<std::string> &src,
                   const std::vector<std::string> &tgt,
                   const std::vector<std::string> &cls,
                   const std::vector<std::string> &perm) {
  for (const auto &s : src)
    for (const auto &t : tgt)
      for (const auto &c : cls)
        for (const auto &p : perm)
          out.push_back({kCmdNormalPerm, subcmd, {s, t, c, p}});
}

bool parse_statement(const std::string &line, std::vector<Atomic> &out) {
  auto t = tokenize(line);
  if (t.empty())
    return true;
  if (t[0] == "#")
    return true;

  size_t i = 1;
  const std::string &op = t[0];

  auto sub_for = [](const std::string &o) -> uint32_t {
    if (o == "allow") return kSubAllow;
    if (o == "deny") return kSubDeny;
    if (o == "auditallow") return kSubAuditallow;
    if (o == "dontaudit") return kSubDontaudit;
    return kCmdMany;
  };

  if (op == "allow" || op == "deny" || op == "auditallow" ||
      op == "dontaudit") {
    std::vector<std::string> src, tgt, cls, perm;
    if (!parse_seobj(t, i, src) || !parse_seobj(t, i, tgt) ||
        !parse_seobj(t, i, cls) || !parse_seobj(t, i, perm))
      return false;
    expand_normal(out, sub_for(op), src, tgt, cls, perm);
    return true;
  }

  if (op == "allowxperm" || op == "auditallowxperm" ||
      op == "dontauditxperm") {
    std::vector<std::string> src, tgt, cls, set;
    std::string oper;
    if (!parse_seobj(t, i, src) || !parse_seobj(t, i, tgt) ||
        !parse_seobj(t, i, cls) || !parse_seobj_single(t, i, oper) ||
        !parse_seobj(t, i, set))
      return false;
    if (oper != "ioctl")
      return true; // only ioctl ranges are supported; skip others
    uint32_t sub = op == "allowxperm"     ? kSubXAllow
                   : op == "auditallowxperm" ? kSubXAuditallow
                                             : kSubXDontaudit;
    for (const auto &s : src)
      for (const auto &tg : tgt)
        for (const auto &c : cls)
          for (const auto &r : set)
            out.push_back({kCmdXperm, sub, {s, tg, c, oper, r}});
    return true;
  }

  if (op == "permissive" || op == "enforce") {
    std::vector<std::string> type;
    if (!parse_seobj(t, i, type))
      return false;
    for (const auto &x : type)
      out.push_back({kCmdTypeState,
                     op == "permissive" ? kSubPermissive : kSubEnforce,
                     {x}});
    return true;
  }

  if (op == "type") {
    std::string name;
    if (!parse_seobj_single(t, i, name))
      return false;
    std::vector<std::string> attrs;
    if (i >= t.size())
      attrs.push_back("domain"); // KernelSU defaults to domain
    else if (!parse_seobj(t, i, attrs))
      return false;
    for (const auto &a : attrs)
      out.push_back({kCmdType, 0, {name, a}});
    return true;
  }

  if (op == "typeattribute" || op == "attradd") {
    std::vector<std::string> type, attr;
    if (!parse_seobj(t, i, type) || !parse_seobj(t, i, attr))
      return false;
    for (const auto &x : type)
      for (const auto &a : attr)
        out.push_back({kCmdTypeAttr, 0, {x, a}});
    return true;
  }

  if (op == "attribute") {
    std::string name;
    if (!parse_seobj_single(t, i, name))
      return false;
    out.push_back({kCmdAttr, 0, {name}});
    return true;
  }

  if (op == "type_transition" || op == "name_transition") {
    std::string s, tg, c, d, obj;
    if (!parse_seobj_single(t, i, s) || !parse_seobj_single(t, i, tg) ||
        !parse_seobj_single(t, i, c) || !parse_seobj_single(t, i, d))
      return false;
    if (i < t.size()) {
      if (!parse_seobj_single(t, i, obj))
        return false;
      out.push_back({kCmdTypeTransition, 0, {s, tg, c, d, obj}});
    } else {
      out.push_back({kCmdTypeTransition, 0, {s, tg, c, d, "*"}});
    }
    return true;
  }

  if (op == "type_change" || op == "type_member") {
    std::string s, tg, c, d;
    if (!parse_seobj_single(t, i, s) || !parse_seobj_single(t, i, tg) ||
        !parse_seobj_single(t, i, c) || !parse_seobj_single(t, i, d))
      return false;
    out.push_back({kCmdTypeChange,
                   op == "type_change" ? kSubChangeChange : kSubChangeMember,
                   {s, tg, c, d}});
    return true;
  }

  if (op == "genfscon") {
    std::string fs, path, ctx;
    if (!parse_seobj_single(t, i, fs) || !parse_seobj_single(t, i, path) ||
        !parse_seobj_single(t, i, ctx))
      return false;
    out.push_back({kCmdGenfscon, 0, {fs, path, ctx}});
    return true;
  }

  // Unknown statement: ignore, matching KernelSU's non-strict behaviour.
  return true;
}

std::vector<Atomic> parse_policy(const std::string &text) {
  std::vector<Atomic> out;
  std::string line;
  auto flush = [&]() {
    std::string trimmed = line;
    size_t b = trimmed.find_first_not_of(" \t\r");
    if (b != std::string::npos)
      trimmed.erase(0, b);
    if (!trimmed.empty())
      parse_statement(trimmed, out);
    line.clear();
  };
  for (char c : text) {
    if (c == '\n' || c == ';')
      flush();
    else
      line.push_back(c);
  }
  flush();
  return out;
}

// ---- fd + transport -------------------------------------------------------

int find_driver_fd() {
  DIR *dir = ::opendir("/proc/self/fd");
  if (!dir)
    return -1;
  int found = -1;
  struct dirent *ent;
  while ((ent = ::readdir(dir)) != nullptr) {
    if (ent->d_name[0] < '0' || ent->d_name[0] > '9')
      continue;
    const std::string link = std::string("/proc/self/fd/") + ent->d_name;
    char target[256];
    const ssize_t n = ::readlink(link.c_str(), target, sizeof(target) - 1);
    if (n <= 0)
      continue;
    target[n] = '\0';
    if (std::strstr(target, "[fmac_ctl]")) {
      found = std::atoi(ent->d_name);
      break;
    }
  }
  ::closedir(dir);
  return found;
}

int driver_fd() {
  static int cached = -2;
  if (cached != -2)
    return cached;
  // Ask the kernel to install the fd for us (root-gated), then scan for it.
  ::prctl(kNksuPrctlGetDriverFd, 0, 0, 0, 0);
  cached = find_driver_fd();
  return cached;
}

bool send_batch(const std::vector<uint8_t> &payload, int *applied) {
  const int fd = driver_fd();
  if (fd < 0) {
    std::cerr << "[module] cannot obtain the nksu control fd, sepolicy skipped"
              << std::endl;
    return false;
  }

  std::vector<uint8_t> buf(sizeof(struct fmac_ioc) + payload.size());
  auto *ioc = reinterpret_cast<struct fmac_ioc *>(buf.data());
  ioc->flag = kIocSetSepolicy;
  ioc->size = static_cast<uint32_t>(payload.size());
  if (!payload.empty())
    std::memcpy(ioc->data, payload.data(), payload.size());

  const int ret = ::ioctl(fd, NKSU_IOC_CMD, buf.data());
  if (ret < 0) {
    std::cerr << "[module] IOC_SET_SEPOLICY failed: " << std::strerror(errno)
              << std::endl;
    return false;
  }

  *applied = ret;
  return true;
}

} // namespace

void load_sepolicy_rule() {
  foreach_module(ModuleType::Active, [](const std::string &module) {
    const std::string rule = utils::join(module, "sepolicy.rule");
    if (!utils::is_file(rule))
      return;

    std::string text;
    if (!utils::read_file(rule, text)) {
      std::cerr << "[module] cannot read " << rule << std::endl;
      return;
    }

    const std::vector<Atomic> statements = parse_policy(text);
    if (statements.empty())
      return;

    std::vector<uint8_t> payload;
    payload.reserve(statements.size() * 64);
    for (const auto &s : statements)
      encode_atomic(payload, s);

    int applied = 0;
    if (send_batch(payload, &applied)) {
      std::cout << "[module] load sepolicy.rule: " << rule << " ("
                << statements.size() << " stmt)" << std::endl;
    } else {
      std::cerr << "[module] failed to apply " << rule << std::endl;
    }
  });
}

} // namespace modules
