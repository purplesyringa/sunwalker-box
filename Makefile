MACHINE := $(subst -linux-gnu,,$(shell $(CC) -print-multiarch))
TARGET := $(MACHINE)-unknown-linux-musl

.PHONY: sunwalker_box test

all: sunwalker_box

sunwalker_box: target/seccomp_filter target/exec_wrapper
	cargo +nightly build --target=$(TARGET) -Z build-std=std,panic_abort --release
	cp target/$(TARGET)/release/sunwalker_box sunwalker_box

target/seccomp_filter: target/$(MACHINE)/seccomp_filter
	cp $^ $@
target/x86_64/seccomp_filter: src/linux/x86_64/seccomp_filter.asm
	mkdir -p target/x86_64 && seccomp-tools asm $^ -o $@ -f raw
target/aarch64/seccomp_filter: src/linux/aarch64/seccomp_filter.asm
	mkdir -p target/aarch64 && seccomp-tools asm $^ -o $@ -f raw

target/exec_wrapper: target/$(MACHINE)/exec_wrapper.o
	ld $^ -o $@ -static -n -s
target/x86_64/exec_wrapper.o: src/linux/x86_64/exec_wrapper.asm
	mkdir -p target/x86_64 && nasm $^ -o $@ -f elf64
target/aarch64/exec_wrapper.o: src/linux/aarch64/exec_wrapper.asm
	mkdir -p target/aarch64 && aarch64-linux-gnu-as $^ -o $@


test:
	cd sandbox_tests && ./test.py
