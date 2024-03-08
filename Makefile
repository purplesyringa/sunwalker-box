ARCH := $(shell $(CC) -dumpmachine | cut -d- -f1)
TARGET := $(ARCH)-unknown-linux-musl

RUSTFLAGS := $(RUSTFLAGSADD) --remap-path-prefix ${HOME}/.rustup=~/.rustup --remap-path-prefix ${HOME}/.cargo=~/.cargo --remap-path-prefix $(shell pwd)=.

ifeq ($(ARCH),aarch64)
RUSTFLAGS += -C link-arg=-lgcc
endif

# This lists all the registers GCC typically thinks of as callee-saved (except sp). We explicitly tell GCC to treat them
# as caller-saved to avoid stack spills in prefork code.
ifeq ($(ARCH),x86_64)
CALLEE_SAVED_REGISTERS := rbx r12 r13 r14 r15
endif
ifeq ($(ARCH),aarch64)
CALLEE_SAVED_REGISTERS := x19 x20 x21 x22 x23 x24 x25 x26 x27 x28
endif

CXX_OPTIONS := -nostartfiles -nostdlib -O2 -std=c++20 -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-exceptions -fno-stack-clash-protection -fconserve-stack -fwhole-program $(patsubst %,-fcall-used-%,$(CALLEE_SAVED_REGISTERS))

CARGO_TARGET := $(shell echo "$(TARGET)" | tr a-z- A-Z_)
CARGO := CARGO_TARGET_$(CARGO_TARGET)_LINKER="$(CC)" RUSTFLAGS="$(RUSTFLAGS)" cargo +nightly
CARGO_OPTIONS := --target $(TARGET) -Z build-std=std,panic_abort -Z build-std-features=panic_immediate_abort --release

SECCOMP_FILTERS := filter

.PHONY: target/$(TARGET)/release/sunwalker_box test clean bloat check clippy

all: sunwalker_box

sunwalker_box: $(ARCH)-sunwalker_box
	cp $^ $@
$(ARCH)-sunwalker_box: target/$(TARGET)/release/sunwalker_box
	strip $^ -o $@

DEPS := $(patsubst %,target/%.seccomp.out,$(SECCOMP_FILTERS)) target/exec_wrapper target/sunwalker.ko target/syscall_table.offsets

target/$(TARGET)/release/sunwalker_box: $(DEPS)
	$(CARGO) build $(CARGO_OPTIONS)

bloat: $(DEPS)
	$(CARGO) bloat $(CARGO_OPTIONS) $(OPTIONS)

check: $(DEPS)
	$(CARGO) check $(CARGO_OPTIONS) $(OPTIONS)

clippy: $(DEPS)
	$(CARGO) clippy $(CARGO_OPTIONS) $(OPTIONS)

target/libc.hpp: generate_syscall_table.py
	mkdir -p target && CC=$(CC) python3 $< >$@

target/%.seccomp.out: src/linux/$(ARCH)/%.seccomp
	mkdir -p target && seccomp-tools asm $^ -o $@ -f raw

target/exec_wrapper: cxx/exec_wrapper.cpp cxx/exec_wrapper.ld $(shell find cxx -maxdepth 1 -name '*.hpp') target/libc.hpp
	$(CXX) $< -o $@ -T cxx/exec_wrapper.ld -static-pie $(CXX_OPTIONS) -s

target/sunwalker.ko: kmodule/$(ARCH)/sunwalker.ko
	mkdir -p target && cp $^ $@
kmodule/x86_64/sunwalker.ko:
	touch $@
kmodule/aarch64/sunwalker.ko: kmodule/aarch64/sunwalker.c
	$(MAKE) -C kmodule/aarch64

# This actually generates more files; we list just one and depend on just one
target/syscall_table.offsets: generate_string_tables.py
	mkdir -p target && CC=$(CC) python3 generate_string_tables.py


test:
	cd sandbox_tests && ./test.py $(ARCH) $(TESTS)

clean:
	rm -r target sunwalker_box *-sunwalker_box kmodule/*/Module.symvers kmodule/*/modules.order kmodule/*/sunwalker.ko kmodule/*/sunwalker.mod* kmodule/*/sunwalker.o || true
