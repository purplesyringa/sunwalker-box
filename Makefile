.PHONY: sunwalker_box

all: sunwalker_box

sunwalker_box: target/seccomp_filter
	cargo +nightly build --target=x86_64-unknown-linux-musl -Z build-std=std,panic_abort --release
	cp target/x86_64-unknown-linux-musl/release/sunwalker_box sunwalker_box

target/seccomp_filter: src/linux/seccomp_filter.asm
	mkdir -p target && seccomp-tools asm $^ -o $@ -f raw


test:
	cd sandbox_tests && ./test.py
