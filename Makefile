TARGET := $(shell $(CC) -print-multiarch)

.PHONY: sunwalker_box test

all: sunwalker_box

sunwalker_box: target/seccomp_filter target/exec_wrapper
	cargo +nightly build --target=x86_64-unknown-linux-musl -Z build-std=std,panic_abort --release
	cp target/x86_64-unknown-linux-musl/release/sunwalker_box sunwalker_box

target/seccomp_filter: target/$(TARGET)/seccomp_filter
	cp $^ $@
target/x86_64-linux-gnu/seccomp_filter: src/linux/x86_64-linux-gnu/seccomp_filter.asm
	mkdir -p target/x86_64-linux-gnu && seccomp-tools asm $^ -o $@ -f raw
target/aarch64-linux-gnu/seccomp_filter: src/linux/aarch64-linux-gnu/seccomp_filter.asm
	mkdir -p target/aarch64-linux-gnu && seccomp-tools asm $^ -o $@ -f raw

target/exec_wrapper: target/$(TARGET)/exec_wrapper.o
	ld $^ -o $@ -static -n -s
target/x86_64-linux-gnu/exec_wrapper.o: src/linux/x86_64-linux-gnu/exec_wrapper.asm
	mkdir -p target/x86_64-linux-gnu && nasm $^ -o $@ -f elf64
target/aarch64-linux-gnu/exec_wrapper.o: src/linux/aarch64-linux-gnu/exec_wrapper.asm
	mkdir -p target/aarch64-linux-gnu && aarch64-linux-gnu-as $^ -o $@


test:
	cd sandbox_tests && ./test.py
