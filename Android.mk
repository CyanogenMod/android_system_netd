LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES:=                                      \
                  BandwidthController.cpp              \
                  CommandListener.cpp                  \
                  DnsProxyListener.cpp                 \
                  MDnsSdListener.cpp                   \
                  IdletimerController.cpp              \
                  NatController.cpp                    \
                  NetdCommand.cpp                      \
                  NetdConstants.cpp                    \
                  NetlinkHandler.cpp                   \
                  NetlinkManager.cpp                   \
                  PanController.cpp                    \
                  PppController.cpp                    \
                  ResolverController.cpp               \
                  SecondaryTableController.cpp         \
                  TetherController.cpp                 \
                  ThrottleController.cpp               \
                  oem_iptables_hook.cpp                \
                  logwrapper.c                         \
                  main.cpp                             \


LOCAL_MODULE:= netd

LOCAL_C_INCLUDES := $(KERNEL_HEADERS) \
                    $(LOCAL_PATH)/../bluetooth/bluedroid/include \
                    $(LOCAL_PATH)/../bluetooth/bluez-clean-headers \
                    external/mdnsresponder/mDNSShared \
                    external/openssl/include \
                    external/stlport/stlport \
                    bionic \
                    bionic/libc/private \
                    $(call include-path-for, libhardware_legacy)/hardware_legacy

LOCAL_CFLAGS := -Werror=format

LOCAL_SHARED_LIBRARIES := libstlport libsysutils libcutils libnetutils \
                          libcrypto libhardware_legacy libmdnssd

ifdef USES_TI_MAC80211
  LOCAL_SRC_FILES += SoftapControllerTI.cpp
else
  LOCAL_SRC_FILES += SoftapController.cpp
endif


ifneq ($(BOARD_HOSTAPD_DRIVER),)
  LOCAL_CFLAGS += -DHAVE_HOSTAPD
  ifneq ($(BOARD_HOSTAPD_DRIVER_NAME),)
    LOCAL_CFLAGS += -DHOSTAPD_DRIVER_NAME=\"$(BOARD_HOSTAPD_DRIVER_NAME)\"
  endif
endif

ifneq ($(BOARD_HOSTAPD_NO_ENTROPY),)
  LOCAL_CFLAGS += -DHOSTAPD_NO_ENTROPY
endif

ifeq ($(BOARD_HAVE_BLUETOOTH),true)
  LOCAL_SHARED_LIBRARIES := $(LOCAL_SHARED_LIBRARIES) libbluedroid
  LOCAL_CFLAGS := $(LOCAL_CFLAGS) -DHAVE_BLUETOOTH
endif

ifeq ($(WIFI_DRIVER_HAS_LGE_SOFTAP),true)
  LOCAL_CFLAGS += -DLGE_SOFTAP
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
