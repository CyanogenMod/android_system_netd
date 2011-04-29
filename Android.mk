BUILD_NETD := false
ifneq ($(TARGET_SIMULATOR),true)
    BUILD_NETD := true
endif

ifeq ($(BUILD_NETD),true)

LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

#ifdef OMAP_ENHANCEMENT
ifdef BOARD_SOFTAP_DEVICE
DK_ROOT = hardware/ti/wlan/$(BOARD_SOFTAP_DEVICE)_softAP
OS_ROOT = $(DK_ROOT)/platforms
STAD    = $(DK_ROOT)/stad
UTILS   = $(DK_ROOT)/utils
TWD     = $(DK_ROOT)/TWD
COMMON  = $(DK_ROOT)/common
TXN     = $(DK_ROOT)/Txn
CUDK    = $(DK_ROOT)/CUDK

WILINK_INCLUDES = $(STAD)/Export_Inc               \
                  $(STAD)/src/Application          \
                  $(UTILS)                         \
                  $(OS_ROOT)/os/linux/inc          \
                  $(OS_ROOT)/os/common/inc         \
                  $(TWD)/TWDriver                  \
                  $(TWD)/FirmwareApi               \
                  $(TWD)/TwIf                      \
                  $(TWD)/FW_Transfer/Export_Inc    \
                  $(TXN)                           \
                  $(CUDK)/configurationutility/inc \
                  external/hostapd                 \
                  $(CUDK)/os/common/inc
endif
#endif

LOCAL_SRC_FILES:=                                      \
                  main.cpp                             \
                  CommandListener.cpp                  \
                  DnsProxyListener.cpp                 \
                  NetdCommand.cpp                      \
                  NetlinkManager.cpp                   \
                  NetlinkHandler.cpp                   \
                  logwrapper.c                         \
                  TetherController.cpp                 \
                  NatController.cpp                    \
                  PppController.cpp                    \
                  PanController.cpp                    \
                  ThrottleController.cpp               \
                  ResolverController.cpp

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
ifdef WIFI_DRIVER_HAS_LGE_SOFTAP
LOCAL_CFLAGS += -DLGE_SOFTAP
endif

#ifdef OMAP_ENHANCEMENT
ifdef BOARD_SOFTAP_DEVICE
LOCAL_CFLAGS += -D__BYTE_ORDER_LITTLE_ENDIAN
LOCAL_STATIC_LIBRARIES := libhostapdcli
LOCAL_C_INCLUDES += $(WILINK_INCLUDES)
LOCAL_SRC_FILES += SoftapControllerTI.cpp
else ifeq ($(WIFI_DRIVER_MODULE_NAME),ar6000)
  ifneq ($(WIFI_DRIVER_MODULE_PATH),rfkill)
    LOCAL_CFLAGS += -DWIFI_MODULE_PATH=\"$(WIFI_DRIVER_MODULE_PATH)\"
  endif
LOCAL_C_INCLUDES += external/wpa_supplicant external/hostapd
LOCAL_SRC_FILES += SoftapControllerATH.cpp
else
LOCAL_SRC_FILES += SoftapController.cpp
endif
#endif

LOCAL_SHARED_LIBRARIES := libsysutils libcutils libnetutils libcrypto libhardware_legacy

ifeq ($(WIFI_DRIVER_MODULE_NAME),ar6000)
LOCAL_SHARED_LIBRARIES := $(LOCAL_SHARED_LIBRARIES) libwpa_client
endif

ifeq ($(BOARD_HAVE_BLUETOOTH),true)
  LOCAL_SHARED_LIBRARIES := $(LOCAL_SHARED_LIBRARIES) libbluedroid
  LOCAL_CFLAGS := $(LOCAL_CFLAGS) -DHAVE_BLUETOOTH
endif

ifeq ($(BOARD_USE_HTC_USB_FUNCTION_SWITCH),true)
  LOCAL_CFLAGS += -DUSE_HTC_USB_FUNCTION_SWITCH
endif

ifneq ($(BOARD_CUSTOM_USB_CONTROLLER),)
  LOCAL_SRC_FILES += $(BOARD_CUSTOM_USB_CONTROLLER)
else
  LOCAL_SRC_FILES += UsbController.cpp
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
