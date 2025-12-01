#!/bin/bash

set -e


build() {
	cargo build --release --target=aarch64-unknown-linux-gnu 
}


package() {
	cargo deb  --profile=release --target=aarch64-unknown-linux-gnu --no-build
}


# main:
build
package