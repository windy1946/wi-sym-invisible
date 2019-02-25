LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE    := main-arm64
LOCAL_CFLAGS += -fpie -fno-stack-protector -fno-asynchronous-unwind-tables -fno-exceptions -fno-rtti -fno-unwind-tables
LOCAL_LDFLAGS += -llog
LOCAL_SRC_FILES := main.c

#include $(BUILD_SHARED_LIBRARY)
include $(BUILD_EXECUTABLE)