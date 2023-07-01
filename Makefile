.PHONY: sunwalker_box test

all: sunwalker_box

sunwalker_box: target/seccomp_filter target/exec_wrapper
	cargo +nightly build --target=x86_64-unknown-linux-musl -Z build-std=std,panic_abort --release
	cp target/x86_64-unknown-linux-musl/release/sunwalker_box sunwalker_box

target/seccomp_filter: src/linux/seccomp_filter.asm
	mkdir -p target && seccomp-tools asm $^ -o $@ -f raw

target/exec_wrapper: target/exec_wrapper.o
	ld $^ -o $@ -static -n -s
target/exec_wrapper.o: src/linux/exec_wrapper.asm
	mkdir -p target && nasm $^ -o $@ -f elf64


test:
	cd sandbox_tests && ./test.py
