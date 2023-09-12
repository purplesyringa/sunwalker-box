ARCH := $(shell musl-gcc -dumpmachine | cut -d- -f1)
TARGET := $(ARCH)-unknown-linux-musl

SECCOMP_FILTERS := filter

RUSTFLAGS := --remap-path-prefix ${HOME}/.rustup=~/.rustup --remap-path-prefix ${HOME}/.cargo=~/.cargo --remap-path-prefix $(shell pwd)=.

ifeq ($(ARCH),aarch64)
RUSTFLAGS += -C link-arg=-lgcc
endif

.PHONY: target/$(TARGET)/release/sunwalker_box test clean

all: sunwalker_box

sunwalker_box: $(ARCH)-sunwalker_box
	cp $^ $@
$(ARCH)-sunwalker_box: target/$(TARGET)/release/sunwalker_box
	cp $^ $@
target/$(TARGET)/release/sunwalker_box: $(patsubst %,target/%.seccomp.out,$(SECCOMP_FILTERS)) target/exec_wrapper target/sunwalker.ko target/syscall_table.offsets
	RUSTFLAGS="$(RUSTFLAGS)" cargo +nightly build --target=$(TARGET) -Z build-std=std,panic_abort --release --config target.$(ARCH)-unknown-linux-musl.linker=\"$(ARCH)-linux-gnu-gcc\"

target/%.seccomp.out: src/linux/$(ARCH)/%.seccomp
	mkdir -p target && seccomp-tools asm $^ -o $@ -f raw

target/exec_wrapper: target/$(ARCH)/exec_wrapper.o
	$(ARCH)-linux-gnu-gcc $^ -o $@ -static -nostartfiles -n -s
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
	mkdir -p target && python3 generate_string_tables.py $(ARCH)


test:
	cd sandbox_tests && ./test.py $(ARCH)

clean:
	rm -r target sunwalker_box *-sunwalker_box kmodule/*/Module.symvers kmodule/*/modules.order kmodule/*/sunwalker.ko kmodule/*/sunwalker.mod* kmodule/*/sunwalker.o || true
