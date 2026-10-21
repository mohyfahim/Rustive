#!/bin/bash

set -e # Exit on any error

APP_NAME="rustive"
VERSION="0.3.0"
# CRITICAL: Change this to match your OpenWrt router's exact architecture string
OPENWRT_ARCH="mipsel_24kc"
TARGET="mipsel-unknown-linux-musl"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "🚀 Building Rust binary for $TARGET..."
bash $SCRIPT_DIR/cross.sh

echo "📦 Preparing IPK staging directory..."
STAGING_DIR="target/ipk_build"
rm -rf $STAGING_DIR
mkdir -p $STAGING_DIR/{data/usr/bin,control}

# 1. Prepare the Data Archive (The actual files to install)
cp target/$TARGET/release/$APP_NAME $STAGING_DIR/data/usr/bin/
chmod 755 $STAGING_DIR/data/usr/bin/$APP_NAME
cp packaging/capture_wrt.sh $STAGING_DIR/data/usr/bin/capture.sh
chmod 755 $STAGING_DIR/data/usr/bin/capture.sh
cp packaging/white_list_wrt.sh $STAGING_DIR/data/usr/bin/white_list.sh
chmod 755 $STAGING_DIR/data/usr/bin/white_list.sh
mkdir -p $STAGING_DIR/data/etc/rustive
cp packaging/config.toml $STAGING_DIR/data/etc/rustive/config.toml
chmod 644 $STAGING_DIR/data/etc/rustive/config.toml
cp packaging/dhcp_script_wrt.sh $STAGING_DIR/data/etc/rustive/dhcp_script.sh
chmod 755 $STAGING_DIR/data/etc/rustive/dhcp_script.sh

# (Optional) Copy OpenWrt init.d scripts or config files here
mkdir -p $STAGING_DIR/data/etc/init.d
cp packaging/rustive.init $STAGING_DIR/data/etc/init.d/rustive
chmod 755 $STAGING_DIR/data/etc/init.d/rustive

# 2. Prepare the Control File (Package metadata)
cat <<EOF >$STAGING_DIR/control/control
Package: $APP_NAME
Version: $VERSION
Architecture: $OPENWRT_ARCH
Maintainer: Mohy <fahimohy@gmail.com>
Section: utils
Priority: optional
Description: My Rust application compiled for OpenWrt Mipsel.
EOF
printf '/etc/rustive/config.toml\n' >$STAGING_DIR/control/conffiles

# 3. Compress the Archives
echo "🗜️ Compressing archives..."
cd $STAGING_DIR/data
tar --owner=0 --group=0 -czvf ../data.tar.gz ./*
cd ../control
tar --owner=0 --group=0 -czvf ../control.tar.gz ./*
cd ..

# 4. Create the debian-binary magic file
echo "2.0" >debian-binary

# 5. Build the final .ipk file
IPK_NAME="${APP_NAME}_${VERSION}_${OPENWRT_ARCH}.ipk"
tar --owner=0 --group=0 -czvf ../../$IPK_NAME control.tar.gz data.tar.gz debian-binary

# 6. Cleanup
cd ../../
rm -rf $STAGING_DIR

echo "✅ Successfully created OpenWrt package: $IPK_NAME"
