ARCH := $(shell $(CC) -dumpmachine | cut -d- -f1)
CLANG := clang-16
TARGET := $(ARCH)-unknown-linux-musl
TARGET_FREESTANDING := $(ARCH)-unknown-none
SYSROOT := $(shell rustc --print sysroot)

SECCOMP_FILTERS := filter filter_restricted

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
target/$(TARGET)/release/sunwalker_box: $(patsubst %,target/%.seccomp.out,$(SECCOMP_FILTERS)) target/exec_wrapper target/syscall_slave target/syscall_loop.bin target/sunwalker.ko target/syscall_table.offsets target/parasite target/parasite.info
	RUSTFLAGS="$(RUSTFLAGS)" cargo +nightly build --target $(TARGET) -Z build-std=std,panic_abort -Z build-std-features= --release --config target.$(ARCH)-unknown-linux-musl.linker=\"$(CC)\"

target/parasite.info: target/parasite
	objdump -ht -j prog $< | { \
		echo "ParasiteInfo {"; \
		awk '/0 prog/ {print "prog_size: 0x" $$3 ", prog_file_offset: 0x" $$6 ","} /_checkpoint/ {print "checkpoint_vma: 0x" $$1 ","} /_start/ {print "start_vma: 0x" $$1 ","} /START_INFORMATION/ {print "start_information_vma: 0x" $$1 ","}'; \
		echo "}"; \
	} >$@
target/parasite: $(shell find parasite/src -name *.rs) parasite/src/entry.S parasite/src/libc.rs target/syscall_table.offsets
	-rm target/$(TARGET_FREESTANDING)/release/deps/parasite*.ll
	touch parasite/src/lib.rs
	cd parasite && RUSTFLAGS="$(RUSTFLAGS) -C relocation-model=pie --emit llvm-ir" cargo +nightly rustc --target $(TARGET_FREESTANDING) -Z build-std=core,panic_abort --release
	sed -i -E -e 's/llvm.(memcpy|memmove).p0.p0.i64/\1/g' -e 's/llvm.memset.p0.i64/memset/g' -e 's/"probe-stack"="inline-asm"//g' target/$(TARGET_FREESTANDING)/release/deps/*.ll
	$(CLANG) target/$(TARGET_FREESTANDING)/release/deps/*.ll parasite/src/entry.S -static-pie -ffreestanding -nodefaultlibs -nostartfiles -flto -Wl,--gc-sections -Wl,-pie -T parasite/script.ld -O1 -o $@
parasite/src/libc.rs: generate_constant_table.py
	CC=$(CC) python3 generate_constant_table.py >$@

target/%.seccomp.out: src/linux/$(ARCH)/%.seccomp
	mkdir -p target && seccomp-tools asm $^ -o $@ -f raw

target/exec_wrapper: target/$(ARCH)/exec_wrapper.o
	$(CC) $^ -o $@ -static -nostartfiles -n -s
target/x86_64/exec_wrapper.o: src/linux/x86_64/exec_wrapper.asm
	mkdir -p target/x86_64 && nasm $^ -o $@ -f elf64
target/aarch64/exec_wrapper.o: src/linux/aarch64/exec_wrapper.asm
	mkdir -p target/aarch64 && aarch64-linux-gnu-as $^ -o $@

target/syscall_slave: target/$(ARCH)/syscall_slave.o
	$(ARCH)-linux-gnu-gcc $^ -o $@ -static -nostartfiles -n -s
target/x86_64/syscall_slave.o: src/linux/x86_64/syscall_slave.asm
	mkdir -p target/x86_64 && nasm $^ -o $@ -f elf64
target/aarch64/syscall_slave.o: src/linux/aarch64/syscall_slave.asm
	mkdir -p target/aarch64 && aarch64-linux-gnu-as $^ -o $@

target/syscall_loop.bin: target/syscall_loop
	$(ARCH)-linux-gnu-objcopy -O binary --only-section=.text $^ $@
target/syscall_loop: target/$(ARCH)/syscall_loop.o
	$(ARCH)-linux-gnu-gcc $^ -o $@ -static -nostartfiles -n -s
target/x86_64/syscall_loop.o: src/linux/x86_64/syscall_loop.asm
	mkdir -p target/x86_64 && nasm $^ -o $@ -f elf64
target/aarch64/syscall_loop.o: src/linux/aarch64/syscall_loop.asm
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
