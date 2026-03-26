#!/bin/bash
cd /mnt/d/Project/self/ap_policy
export ANDROID_NDK_HOME=/mnt/d/Tools/android-ndk-r23c/
export PATH=/mnt/d/Tools/android-ndk-r23c/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH
cargo build --target aarch64-linux-android --release
