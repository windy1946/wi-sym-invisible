LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE    := test
LOCAL_CFLAGS += -fpie -fno-stack-protector -fno-asynchronous-unwind-tables -fno-exceptions -fno-rtti -fno-unwind-tables
LOCAL_LDFLAGS += -llog
LOCAL_SRC_FILES := test.c
include $(BUILD_SHARED_LIBRARY)


include $(CLEAR_VARS)
LOCAL_MODULE    := main
LOCAL_CFLAGS += -fpie -fno-stack-protector -fno-asynchronous-unwind-tables -fno-exceptions -fno-rtti -fno-unwind-tables
LOCAL_LDFLAGS += -llog
LOCAL_SRC_FILES := main.c
include $(BUILD_EXECUTABLE)
