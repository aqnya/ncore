NCORE --- NekoSU userspace tools.
==============================
### How to build
if you wan to build ncore,please install bazel first.
```bash
git clone https://github.com/aqnya/ncore.git
cd ncore
git submodule update --init --recursive
bazel build //:ncore