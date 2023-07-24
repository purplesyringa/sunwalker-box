ARCH := $(subst -linux-gnu,,$(shell $(CC) -print-multiarch))
TARGET := $(ARCH)-unknown-linux-musl

ifeq ($(ARCH),aarch64)
RUSTFLAGS := -C link-arg=-lgcc
endif

.PHONY: target/$(TARGET)/release/sunwalker_box test clean

all: sunwalker_box

sunwalker_box: $(ARCH)-sunwalker_box
	cp $^ $@
$(ARCH)-sunwalker_box: target/$(TARGET)/release/sunwalker_box
	cp $^ $@
target/$(TARGET)/release/sunwalker_box: target/seccomp_filter target/exec_wrapper
	RUSTFLAGS="$(RUSTFLAGS)" cargo +nightly build --target=$(TARGET) -Z build-std=std,panic_abort --release --config target.$(ARCH)-unknown-linux-musl.linker=\"$(ARCH)-linux-musl-gcc\"

target/seccomp_filter: target/$(ARCH)/seccomp_filter
	cp $^ $@
target/x86_64/seccomp_filter: src/linux/x86_64/seccomp_filter.asm
	mkdir -p target/x86_64 && seccomp-tools asm $^ -o $@ -f raw
target/aarch64/seccomp_filter: src/linux/aarch64/seccomp_filter.asm
	mkdir -p target/aarch64 && seccomp-tools asm $^ -o $@ -f raw

target/exec_wrapper: target/$(ARCH)/exec_wrapper.o
	$(ARCH)-linux-gnu-ld $^ -o $@ -static -n -s
target/x86_64/exec_wrapper.o: src/linux/x86_64/exec_wrapper.asm
	mkdir -p target/x86_64 && nasm $^ -o $@ -f elf64
target/aarch64/exec_wrapper.o: src/linux/aarch64/exec_wrapper.asm
	mkdir -p target/aarch64 && aarch64-linux-gnu-as $^ -o $@


test:
	cd sandbox_tests && ./test.py $(ARCH)

clean:
	rm -r target sunwalker_box *-sunwalker_box || true
