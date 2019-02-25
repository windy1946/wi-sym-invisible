LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

ifeq ($(TARGET_ARCH_ABI),arm64-v8a)
  	SYSCALL_SRC=syscall/syscall-arm64.S
	LOCAL_CFLAGS += -DM_ARM64
else ifeq ($(TARGET_ARCH_ABI), armeabi-v7a)
	SYSCALL_SRC=syscall/syscall-armeabi-v7a.S
	LOCAL_CFLAGS += -DM_ARM
else ifeq ($(TARGET_ARCH_ABI), x86)
	SYSCALL_SRC=syscall/syscall-x86.S
	LOCAL_CFLAGS += -DM_X86
endif


LOCAL_MODULE    := shellcode-relocate
LOCAL_CFLAGS += -fpic -fno-stack-protector -fno-asynchronous-unwind-tables -fno-exceptions -fno-rtti -fno-unwind-tables
LOCAL_LDFLAGS += -llog 
LOCAL_SRC_FILES := relocate.c utils.c $(SYSCALL_SRC)

include $(BUILD_SHARED_LIBRARY)
#include $(BUILD_EXECUTABLE)