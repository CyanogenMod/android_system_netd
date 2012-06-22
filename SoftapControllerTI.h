/*
 * Copyright (C) 2008 The Android Open Source Project
 * Copyright 2001-2012 Texas Instruments, Inc. - http://www.ti.com/
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

#define HOSTAPD_SERVICE_NAME "hostapd_bin"
#define HOSTAPD_STATE_PROP "init.svc." HOSTAPD_SERVICE_NAME
#define AP_WAKE_LOCK "hotspot_wake_lock"

#define HOSTAPD_CONF_TEMPLATE_FILE "/system/etc/wifi/hostapd.conf"
#define HOSTAPD_CONF_FILE "/data/misc/wifi/hostapd.conf"

#define HOSTAPD_IFUP_WAIT_RETRIES 20
#define HOSTAPD_START_MAX_RETRIES 100
#define HOSTAPD_START_DELAY_US  100000
#define HOSTAPD_STOP_DELAY_US 100000

#define AP_INTERFACE  "wlan0"

class SoftapController {
    bool mHostapdStarted;
private:
    int stopHostapd();
    int startHostapd();
    int isIfUp(const char *ifname);

public:
    SoftapController();
    virtual ~SoftapController();

    int startSoftap();
    int stopSoftap();
    bool isSoftapStarted();
    int setSoftap(int argc, char *argv[]);
    int fwReloadSoftap(int argc, char *argv[]);
    int clientsSoftap(char **retbuf);
};

#endif
