FROM alpine as builder

RUN \
	apk update && \
	apk add bash binutils curl g++ git linux-headers make musl-dev nasm ruby-dev python3 linux-headers && \
	gem install seccomp-tools && \
	gem install racc && \
	curl --proto '=https' --tlsv1.3 https://sh.rustup.rs -sSf | \
	bash -s -- \
		-y \
		--default-host x86_64-unknown-linux-musl \
		--default-toolchain nightly \
		--component rust-src
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /build
COPY . .
RUN make

FROM scratch
COPY --from=builder /build/sunwalker_box /sunwalker_box
