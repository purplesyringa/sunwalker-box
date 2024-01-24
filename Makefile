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

SECCOMP_FILTERS := filter filter_restricted

.PHONY: target/$(TARGET)/release/sunwalker_box test clean bloat check clippy

all: sunwalker_box

sunwalker_box: $(ARCH)-sunwalker_box
	cp $^ $@
$(ARCH)-sunwalker_box: target/$(TARGET)/release/sunwalker_box
	strip $^ -o $@

DEPS := $(patsubst %,target/%.seccomp.out,$(SECCOMP_FILTERS)) target/exec_wrapper.stripped target/exec_wrapper.itimer_prof target/sunwalker.ko target/syscall_table.offsets target/parasite.bin target/parasite.size target/parasite.result_context_map.json target/parasite.state target/stemcell.stripped target/stemcell.result_context_map.json target/stemcell.relocations target/stemcell.state

target/$(TARGET)/release/sunwalker_box: $(DEPS)
	$(CARGO) build $(CARGO_OPTIONS)

bloat: $(DEPS)
	$(CARGO) bloat $(CARGO_OPTIONS) $(OPTIONS)

check: $(DEPS)
	$(CARGO) check $(CARGO_OPTIONS) $(OPTIONS)

clippy: $(DEPS)
	$(CARGO) clippy $(CARGO_OPTIONS) $(OPTIONS)

target/parasite.bin: target/parasite.text
	sed "$$ s/\x00*$$//g" $< >$@
target/parasite.text: target/parasite
	objcopy -O binary --only-section=.text $< $@
target/parasite.size: target/parasite
	readelf -S $< | awk '/\.text/{ getline; print "0x" $$1 }' >$@
target/parasite.result_context_map: target/parasite
	objcopy -O binary --only-section=.result_context_map $< $@
target/parasite.result_context_map.json: target/parasite.result_context_map generate/context_map.py
	python3 generate/context_map.py <$< >$@
target/parasite.state: target/parasite
	readelf -s $< | awk '/OBJECT.*state/{ print "0x" $$2 }' >$@
target/parasite: cxx/parasite.cpp $(shell find cxx -name '*.hpp') target/libc.hpp
	$(CXX) $< -o $@ -T cxx/parasite.ld -static-pie $(CXX_OPTIONS)

target/stemcell.result_context_map: target/stemcell
	objcopy -O binary --only-section=.result_context_map $< $@
target/stemcell.result_context_map.json: target/stemcell.result_context_map generate/context_map.py
	python3 generate/context_map.py <$< >$@
target/stemcell.relocations: target/stemcell.stripped generate/stemcell_relocations.py
	python3 generate/stemcell_relocations.py $< >$@
target/stemcell.state: target/stemcell
	readelf -s $< | gawk '/OBJECT.*state/{ print strtonum("0x" $$2) - 0xdeadbeef000 }' >$@
target/stemcell.stripped: target/stemcell
	strip -s -R .result_context_map $< -o $@
target/stemcell: cxx/stemcell.cpp $(shell find cxx -name '*.hpp') target/libc.hpp
	$(CXX) $< -o $@ -T cxx/stemcell.ld -static $(CXX_OPTIONS) -Wl,-Ttext=0xdeadbeef000

# Keep the Linux kernel versions in sync with the minimal supported versions listed in README. These
# two assets are not expected to be built by the user, but are merely to make updates easier for the
# sunwalker-box devs (e.g. do `make -B generate/syscall_table_<arch>.json` after updating the
# minimal supported kernel version)
generate/syscall_table_x86_64.json:
	wget --output-document $@ https://raw.githubusercontent.com/mebeim/linux-syscalls/master/db/x86/64/x64/v5.19/table.json
generate/syscall_table_aarch64.json:
	wget --output-document $@ https://raw.githubusercontent.com/mebeim/linux-syscalls/master/db/arm64/64/aarch64/v6.2/table.json
target/libc.hpp: generate/syscall_wrappers.py
	mkdir -p target && ARCH=$(ARCH) python3 $< >$@

target/%.seccomp.out: src/linux/$(ARCH)/%.seccomp
	mkdir -p target && seccomp-tools asm $^ -o $@ -f raw

target/exec_wrapper.stripped: target/exec_wrapper
	strip $^ -o $@
target/exec_wrapper.itimer_prof: target/exec_wrapper
	readelf -s $< | awk '/OBJECT.*itimer_prof/{ print "0x" $$2 }' >$@
target/exec_wrapper: cxx/exec_wrapper.cpp cxx/exec_wrapper.ld $(shell find cxx -maxdepth 1 -name '*.hpp') target/libc.hpp
	$(CXX) $< -o $@ -T cxx/exec_wrapper.ld -static $(CXX_OPTIONS)

target/sunwalker.ko: kmodule/$(ARCH)/sunwalker.ko
	mkdir -p target && cp $^ $@
kmodule/x86_64/sunwalker.ko:
	touch $@
kmodule/aarch64/sunwalker.ko: kmodule/aarch64/sunwalker.c
	$(MAKE) -C kmodule/aarch64

# This actually generates more files; we list just one and depend on just one
target/syscall_table.offsets: generate/string_tables.py
	mkdir -p target && CC=$(CC) python3 $<


test:
	cd sandbox_tests && ./test.py $(ARCH) $(TESTS)

clean:
	rm -r target sunwalker_box *-sunwalker_box kmodule/*/Module.symvers kmodule/*/modules.order kmodule/*/sunwalker.ko kmodule/*/sunwalker.mod* kmodule/*/sunwalker.o || true
