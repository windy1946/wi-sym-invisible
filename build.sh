#!/bin/bash
(
    cd stub/jni
    ndk-build
)

(
    cd elf-tool
    make
)

./elf-tool/main stub/libs/arm64-v8a/libshellcode-relocate.so

ret=$?

if [ $ret != 0 ]; then
    echo run elf-tool fail.
    exit 1
fi

adb push stub/libs/arm64-v8a/libshellcode-relocate.so /data/local/tmp/
