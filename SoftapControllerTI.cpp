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

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/wireless.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

#define LOG_TAG "SoftapControllerTI"
#include <cutils/log.h>
#include <cutils/properties.h>

#include <hardware_legacy/power.h>
#include <private/android_filesystem_config.h>

#include "SoftapControllerTI.h"

SoftapController::SoftapController() {
    mHostapdStarted = false;
}

SoftapController::~SoftapController() {
}

int SoftapController::isIfUp(const char *ifname) {
    int sock, ret;
    struct ifreq ifr;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0) {
        return -1;
    }

    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
    ret = ioctl(sock, SIOCGIFFLAGS, &ifr);
    close(sock);

    if(ret == 0) {
       return ifr.ifr_flags & IFF_UP ? 1 : 0;
    }

    ALOGE("Failed to get interface flags for %s\n", ifname);
    return -1;
}


int SoftapController::startHostapd() {
    int i;
    int ifup;
    char svc_property[PROPERTY_VALUE_MAX] = {'\0'};

    if(mHostapdStarted) {
        ALOGE("hostapd is started");
        return 0;
    }

    if (property_set("ctl.start", HOSTAPD_SERVICE_NAME) < 0) {
        ALOGE("Failed to start hostapd");
        return -1;
    }

    for(i=0; i < HOSTAPD_START_MAX_RETRIES; i++) {
        usleep(HOSTAPD_START_DELAY_US);
        if (property_get(HOSTAPD_STATE_PROP, svc_property, NULL) <= 0)
            continue;
        else if (strcmp(svc_property,"running") != 0)
            continue;
       else
           break;
    }

    if (strcmp(svc_property,"running") != 0) {
        ALOGE("failed to start hostapd. state: %s", svc_property);
        return -1;
    }

    // give hostapd some more time to start and bring interface up
    for(i=0; i < HOSTAPD_IFUP_WAIT_RETRIES; i++) {
        ifup = isIfUp(AP_INTERFACE);
        if(ifup == 1) {
            break;
        }
        usleep(HOSTAPD_START_DELAY_US);
    }

    if(ifup != 1) {
        ALOGE("Interface wasn't brought up by hostapd");
        return -1;
    }

    ALOGD("hostapd started OK");
    mHostapdStarted = true;

    return 0;
}

int SoftapController::stopHostapd() {
    char svc_property[PROPERTY_VALUE_MAX] = {'\0'};

    if (property_get(HOSTAPD_STATE_PROP, svc_property, NULL) > 0) {
        if (strcmp(svc_property, "running") != 0) {
            ALOGD("hostapd not running!");
            return 0;
        }
    }

    if (property_set("ctl.stop", HOSTAPD_SERVICE_NAME) < 0) {
        ALOGE("Failed to stop hostapd service");
    }

    usleep(HOSTAPD_STOP_DELAY_US);
    ALOGD("hostapd successfully stopped");
    mHostapdStarted = false;
    return 0;
}

int SoftapController::startSoftap() {
    // don't do anything here - setSoftap is always called
    return 0;
}

int SoftapController::stopSoftap() {

    if (!mHostapdStarted) {
        ALOGE("Softap is stopped");
        return 0;
    }

    stopHostapd();
    release_wake_lock(AP_WAKE_LOCK);
    return 0;
}

// note: this is valid after setSoftap is called
bool SoftapController::isSoftapStarted() {
    ALOGD("returning isSoftapStarted: %d", mHostapdStarted);
    return mHostapdStarted;
}

int SoftapController::clientsSoftap(char **retbuf)
{
	return 0;
}

/*
 * Arguments:
 *	argv[2] - wlan interface
 *	argv[3] - SSID
 *	argv[4] - Security
 *	argv[5] - Key
 *	argv[6] - Channel
 *	argv[7] - Preamble
 *	argv[8] - Max SCB
 */
int SoftapController::setSoftap(int argc, char *argv[]) {
    int ret = 0;
    char buf[1024];

    ALOGD("%s - %s - %s - %s - %s - %s",argv[2],argv[3],argv[4],argv[5],argv[6],argv[7]);

    if (argc < 4) {
        ALOGE("Softap set - missing arguments");
        return -1;
    }

    FILE* fp = fopen(HOSTAPD_CONF_TEMPLATE_FILE, "r");
    if (!fp) {
       ALOGE("Softap set - hostapd template file read failed");
       return -1;
    }

    FILE* fp2 = fopen(HOSTAPD_CONF_FILE, "w");
    if (!fp2) {
       ALOGE("Softap set - hostapd.conf file read failed");
       fclose(fp);
       return -1;
    }
    while (fgets(buf, sizeof(buf), fp)) {
        if((strncmp(buf, "ssid=",5) == 0) ||
           (strncmp(buf, "wpa=",4) == 0) ||
           (strncmp(buf, "wpa_passphrase=",15) == 0) ||
           (strncmp(buf, "wpa_key_mgmt=",12) == 0) ||
           (strncmp(buf, "wpa_pairwise=",12) == 0) ||
           (strncmp(buf, "rsn_pairwise=",12) == 0) ||
           (strncmp(buf, "interface=",10) == 0)) {
           continue;
        }
        fputs(buf,fp2);
    }

    // Update interface
    sprintf(buf, "interface=%s\n", AP_INTERFACE);
    fputs(buf, fp2);

    // Update SSID
    sprintf(buf, "ssid=%s\n",argv[3]);
    fputs(buf, fp2);

    // Update security
    if(strncmp(argv[4],"wpa2-psk",8) == 0) {
        sprintf(buf, "wpa=2\nwpa_passphrase=%s\nwpa_key_mgmt=WPA-PSK\n"
                  "wpa_pairwise=CCMP\nrsn_pairwise=CCMP\n", argv[5]);
        fputs(buf, fp2);
    }

    if(strncmp(argv[4],"wpa-psk",7) == 0) {
        sprintf(buf, "wpa=1\nwpa_passphrase=%s\nwpa_key_mgmt=WPA-PSK\n"
                  "wpa_pairwise=TKIP\nrsn_pairwise=TKIP\n", argv[5]);
        fputs(buf, fp2);
    }

    fclose(fp);
    fclose(fp2);

    if (chmod(HOSTAPD_CONF_FILE, 0660) < 0) {
        ALOGE("Error changing permissions of %s to 0660: %s",
                HOSTAPD_CONF_FILE, strerror(errno));
        unlink(HOSTAPD_CONF_FILE);
        return -1;
    }

    if (chown(HOSTAPD_CONF_FILE, AID_SYSTEM, AID_WIFI) < 0) {
        ALOGE("Error changing group ownership of %s to %d: %s",
                HOSTAPD_CONF_FILE, AID_WIFI, strerror(errno));
        unlink(HOSTAPD_CONF_FILE);
        return -1;
    }

    // we take the wakelock here because the stop/start is lengthy
    acquire_wake_lock(PARTIAL_WAKE_LOCK, AP_WAKE_LOCK);

    // restart hostapd to update configuration
    ret = stopHostapd();
    if (ret != 0)
        goto fail_switch;

    ret = startHostapd();
    if (ret != 0)
        goto fail_switch;

    ALOGD("hostapd set - Ok");
    return 0;

fail_switch:
    release_wake_lock(AP_WAKE_LOCK);
    ALOGD("hostapd set - failed. AP is off.");

    return ret;
}

/*
 * Arguments:
 *	argv[2] - interface name
 *	argv[3] - AP or STA
 */
int SoftapController::fwReloadSoftap(int argc, char *argv[])
{
    return 0;
}
