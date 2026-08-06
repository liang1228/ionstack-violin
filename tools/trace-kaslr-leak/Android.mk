LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE    := trace_kaslr_leak
LOCAL_SRC_FILES := trace_kaslr_leak.c
LOCAL_CFLAGS    := -Wall -Wextra -O2 -static
LOCAL_LDFLAGS   := -static
include $(BUILD_EXECUTABLE)
