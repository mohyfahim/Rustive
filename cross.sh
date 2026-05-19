#!/bin/bash

CROSS_TOOLCHAIN_VERSION=nightly \
	CROSS_RUSTFLAGS=" -Z unstable-options  -C opt-level=z -C lto=yes -C codegen-units=1 -C panic=immediate-abort -C strip=symbols" \
	cross build --target mipsel-unknown-linux-musl -Z build-std=std,core,alloc --release
