ARCH := $(shell $(CC) -dumpmachine | cut -d- -f1)
TARGET := $(ARCH)-unknown-linux-musl

RUSTFLAGS := $(RUSTFLAGSADD) --remap-path-prefix ${HOME}/.rustup=~/.rustup --remap-path-prefix ${HOME}/.cargo=~/.cargo --remap-path-prefix $(shell pwd)=.

ifeq ($(ARCH),aarch64)
RUSTFLAGS += -C link-arg=-lgcc
endif

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

target/%.seccomp.out: src/linux/$(ARCH)/%.seccomp
	mkdir -p target && seccomp-tools asm $^ -o $@ -f raw

target/exec_wrapper: target/$(ARCH)/exec_wrapper.o
	$(CC) $^ -o $@ -static -nostartfiles -n -s
target/x86_64/exec_wrapper.o: src/linux/x86_64/exec_wrapper.asm
	mkdir -p target/x86_64 && nasm $^ -o $@ -f elf64
target/aarch64/exec_wrapper.o: src/linux/aarch64/exec_wrapper.asm
	mkdir -p target/aarch64 && aarch64-linux-gnu-as $^ -o $@

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
