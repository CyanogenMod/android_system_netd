LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := sock_diag_test
LOCAL_CFLAGS := -Wall -Werror -Wunused-parameter
LOCAL_C_INCLUDES := system/netd/server
LOCAL_SRC_FILES := sock_diag_test.cpp ../server/SockDiag.cpp
LOCAL_MODULE_TAGS := tests
LOCAL_SHARED_LIBRARIES := liblog

include $(BUILD_NATIVE_TEST)

