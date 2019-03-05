#!/bin/bash
(
    cd stub/jni
    ndk-build
)

(
    cd elf-tool
    make
)

(
    cd test/jni
    ndk-build
)

./elf-tool/main test/libs/arm64-v8a/libtest.so stub/libs/arm64-v8a/libshellcode-relocate.so

ret=$?

if [ $ret != 0 ]; then
    echo run elf-tool fail.
    exit 1
fi

adb push test/libs/arm64-v8a/libtest.so /data/local/tmp/

adb push test/libs/arm64-v8a/main /data/local/tmp/