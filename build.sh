#!/bin/bash

set -e

build() {
	cross build --target aarch64-unknown-linux-gnu --release
}

package() {
	cargo deb --profile=release --target=aarch64-unknown-linux-gnu --no-build
}

# main:
build
package
