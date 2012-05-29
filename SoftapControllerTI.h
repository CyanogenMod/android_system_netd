/*
 * Copyright (C) 2008 The Android Open Source Project
 * Copyright 2001-2010 Texas Instruments, Inc. - http://www.ti.com/
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _SOFTAP_CONTROLLER_H
#define _SOFTAP_CONTROLLER_H

#include <stdint.h>

#include <linux/in.h>
#include <net/if.h>
#include <utils/List.h>

#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>

#include "nl80211.h"

#define HOSTAPD_SERVICE_NAME "hostapd_bin"
#define HOSTAPD_STATE_PROP "init.svc." HOSTAPD_SERVICE_NAME
#define AP_WAKE_LOCK "hotspot_wake_lock"

#define HOSTAPD_CONF_TEMPLATE_FILE "/system/etc/wifi/hostapd.conf"
#define HOSTAPD_CONF_FILE "/data/misc/wifi/hostapd.conf"

#define HOSTAPD_START_MAX_RETRIES 20
#define HOSTAPD_START_DELAY_US  500000
#define HOSTAPD_STOP_DELAY_US 500000

#define STA_INTERFACE  "wlan0"
#define AP_INTERFACE   "wlan1"

class SoftapController {
    bool mHostapdStarted;

    struct nl_sock *nl_soc;
    struct nl_cache *nl_cache;
    struct genl_family *nl80211;

    bool mApMode;

private:
    int stopHostapd();
    int startHostapd();

    int initNl();
    void deinitNl();
    int phyLookup();
    static int NlAckHandler(struct nl_msg *msg, void *arg);
    static int NlFinishHandler(struct nl_msg *msg, void *arg);
    static int NlErrorHandler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg);
    int executeNlCmd(const char *iface, enum nl80211_iftype type, uint8_t cmd);
    int switchInterface(bool apMode);
    int getStaChanAndMode(int *chan, int *is_g_mode);
    int executeScanLinkCmd(const char *iface, int *iface_freq);
    static int linkDumpCbHandler(struct nl_msg *msg, void *arg);

public:
    SoftapController();
    virtual ~SoftapController();

    int startDriver(char *iface);
    int stopDriver(char *iface);
    int startSoftap();
    int stopSoftap();
    bool isSoftapStarted();
    int setSoftap(int argc, char *argv[]);
    int fwReloadSoftap(int argc, char *argv[]);
    int clientsSoftap(char **retbuf);
};

#endif
