Building sunwalker-box
======================

sunwalker-box supports x86-64 (AMD64) and aarch64 (ARM64) architectures and requires Linux 5.19+ on x86-64 and Linux 6.2+ on aarch64.

Both build methods generate a `sunwalker_box` executable in the current directory. The executable is statically linked and relatively small (around a megabyte, and smaller in compressed form), so it can be copied to any Linux machine and run without requiring any additional libraries or dependencies.


With Docker
-----------

For x86-64, you can use the `Dockerfile` provided in this repository:

```shell
$ id="$(docker create "$(docker build -q .)" a)" && docker cp "$id:/sunwalker_box" sunwalker_box && docker rm "$id"
```

This generates `sunwalker_box` binary.


Without Docker
--------------

For aarch64, or if you don't want to use Docker, you will need to install the following dependencies:

- Rust, with:
  - Toolchain `nightly-<architecture>-unknown-linux-gnu`, provided by e.g. `rustup toolchain install nightly-x86_64-unknown-linux-gnu`,
  - Target `<target>-unknown-linux-musl`, provided by e.g. `rustup +nightly target add x86_64-unknown-linux-musl`,
  - Component `rust-src`, provided by `rustup component add rust-src`
- GNU make
- GNU C++ compiler, provided on Ubuntu by `g++`
- Linux userspace headers, provided on Ubuntu as `libc6-dev`, on Arch Linux as `linux-api-headers`, and on Alpine as `linux-headers`
- binutils
- Python 3
- `ruby`, provided on Ubuntu by `ruby`
- `gem`, provided on Ubuntu by `ruby-rubygems`
- Ruby headers, provided on Ubuntu by `ruby-dev`
- `seccomp-tools`, provided by `gem install seccomp-tools`
- (aarch64 only) Linux kernel headers, provided on Ubuntu by `linux-headers-$(uname -r)`,
- (sandbox-tests only) `musl-gcc`, provided on Ubuntu by `musl-tools`
- (sandbox-tests only) `pyyaml` python package, provided on Alpine by `py3-yaml`

To build sunwalker-box, use:

```shell
$ make
```

This generates a `sunwalker_box` executable in the current directory.

Cross-compilation for x86-64 is supported by passing `CC=x86_64-linux-gnu-gcc` (or the corresponding cross-compiler for your Linux distribution) to `make`. For aarch64, sunwalker-box should be built natively on the target machine, as it includes a kernel module which is dependent on the exact kernel version.
