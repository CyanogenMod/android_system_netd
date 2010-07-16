BUILD_NETD := false
ifneq ($(TARGET_SIMULATOR),true)
    BUILD_NETD := true
endif

ifeq ($(BUILD_NETD),true)

LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES:=                                      \
                  main.cpp                             \
                  CommandListener.cpp                  \
                  NetdCommand.cpp                      \
                  NetlinkManager.cpp                   \
                  NetlinkHandler.cpp                   \
                  logwrapper.c                         \
                  TetherController.cpp                 \
                  NatController.cpp                    \
                  PppController.cpp                    \
                  PanController.cpp                    \
                  SoftapController.cpp                 \
                  UsbController.cpp                    \
                  ThrottleController.cpp

LOCAL_MODULE:= netd

LOCAL_C_INCLUDES := $(KERNEL_HEADERS) \
                    $(LOCAL_PATH)/../bluetooth/bluedroid/include \
                    $(LOCAL_PATH)/../bluetooth/bluez-clean-headers \
                    external/openssl/include

LOCAL_CFLAGS :=
ifdef WIFI_DRIVER_FW_STA_PATH
LOCAL_CFLAGS += -DWIFI_DRIVER_FW_STA_PATH=\"$(WIFI_DRIVER_FW_STA_PATH)\"
endif
ifdef WIFI_DRIVER_FW_AP_PATH
LOCAL_CFLAGS += -DWIFI_DRIVER_FW_AP_PATH=\"$(WIFI_DRIVER_FW_AP_PATH)\"
endif

LOCAL_SHARED_LIBRARIES := libsysutils libcutils libnetutils libcrypto

ifeq ($(BOARD_HAVE_BLUETOOTH),true)
  LOCAL_SHARED_LIBRARIES := $(LOCAL_SHARED_LIBRARIES) libbluedroid
  LOCAL_CFLAGS := $(LOCAL_CFLAGS) -DHAVE_BLUETOOTH
endif

ifeq ($(BOARD_USE_HTC_USB_FUNCTION_SWITCH),true)
  LOCAL_CFLAGS += -DUSE_HTC_USB_FUNCTION_SWITCH
endif

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_SRC_FILES:=          \
                  ndc.c \

LOCAL_MODULE:= ndc

LOCAL_C_INCLUDES := $(KERNEL_HEADERS)

LOCAL_CFLAGS := 

LOCAL_SHARED_LIBRARIES := libcutils

include $(BUILD_EXECUTABLE)

endif # ifeq ($(BUILD_NETD,true)
