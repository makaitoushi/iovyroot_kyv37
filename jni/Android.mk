LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_ARM_MODE := arm
LOCAL_CFLAGS := -O3 -DNDEBUG --all-warnings --extra-warnings

LOCAL_MODULE    := iovyroot_kyv37
LOCAL_SRC_FILES := main.c 

include $(BUILD_EXECUTABLE)
