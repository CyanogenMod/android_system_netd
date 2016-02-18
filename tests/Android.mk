#
# Copyright (C) 2016 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := sock_diag_test
LOCAL_CFLAGS := -Wall -Werror -Wunused-parameter
LOCAL_C_INCLUDES := system/netd/server
LOCAL_SRC_FILES := sock_diag_test.cpp ../server/SockDiag.cpp
LOCAL_MODULE_TAGS := tests
LOCAL_SHARED_LIBRARIES := liblog
include $(BUILD_NATIVE_TEST)

include $(CLEAR_VARS)
LOCAL_MODULE := netd_test
EXTRA_LDLIBS := -lpthread
LOCAL_SHARED_LIBRARIES += libcutils libutils liblog libnetd_client
LOCAL_STATIC_LIBRARIES += libtestUtil
LOCAL_C_INCLUDES += system/netd/include system/extras/tests/include
LOCAL_SRC_FILES := netd_test.cpp dns_responder.cpp
LOCAL_MODULE_TAGS := eng tests
include $(BUILD_NATIVE_TEST)

