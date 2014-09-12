LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk

LOCAL_SRC_FILES:=                                      \
                  BandwidthController.cpp              \
                  ClatdController.cpp                  \
                  CommandListener.cpp                  \
                  DnsProxyListener.cpp                 \
                  FirewallController.cpp               \
                  IdletimerController.cpp              \
                  InterfaceController.cpp              \
                  MDnsSdListener.cpp                   \
                  NatController.cpp                    \
                  NetdCommand.cpp                      \
                  NetdConstants.cpp                    \
                  NetlinkHandler.cpp                   \
                  NetlinkManager.cpp                   \
                  NetworkController.cpp                \
                  PppController.cpp                    \
                  ResolverController.cpp               \
                  SecondaryTableController.cpp         \
                  SoftapController.cpp                 \
                  TetherController.cpp                 \
                  oem_iptables_hook.cpp                \
                  main.cpp                             \

LOCAL_C_INCLUDES := \
                    external/mdnsresponder/mDNSShared \
                    external/openssl/include \
                    bionic/libc/dns/include \
                    $(call include-path-for, libhardware_legacy)/hardware_legacy

LOCAL_SHARED_LIBRARIES := \
    libsysutils \
    liblog \
    libcutils \
    libnetutils \
    libcrypto \
    libhardware_legacy \
    libmdnssd \
    libdl \
    liblogwrap \

LOCAL_MODULE:= netd
LOCAL_CFLAGS := -Werror=format

include external/stlport/libstlport.mk
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
LOCAL_SRC_FILES:= ndc.c
LOCAL_MODULE:= ndc
LOCAL_SHARED_LIBRARIES := libcutils
include $(BUILD_EXECUTABLE)
