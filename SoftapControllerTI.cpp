/*
 * Copyright (C) 2008 The Android Open Source Project
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

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/wireless.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

#define LOG_TAG "SoftapController"
#include <cutils/log.h>

extern "C" {
#include "hostapd/hostapd_cli.h"
}

#include "privateCmd.h"
#include "CmdInterfaceCodes.h"
#include <cutils/properties.h>
#include "cu_hostapd.h"

#include "SoftapControllerTI.h"
#include <hardware_legacy/power.h>

SoftapController::SoftapController() {
    mPid = 0;
    mSock = socket(AF_INET, SOCK_DGRAM, 0);
    if (mSock < 0)
        LOGE("Failed to open socket");
}

SoftapController::~SoftapController() {
    if (mSock >= 0)
        close(mSock);
}

int SoftapController::startDriver(char *iface) {
    struct iwreq wrq;
    ti_private_cmd_t private_cmd;

    int ret, dummyBuf;

    if (mSock < 0) {
        LOGE("Softap driver start - failed to open socket");
        return -1;
    }
    if (!iface || (iface[0] == '\0')) {
        LOGD("Softap driver start - wrong interface");
        return -1;
    }

    private_cmd.cmd = DRIVER_START_PARAM;
    private_cmd.flags = PRIVATE_CMD_SET_FLAG;
    private_cmd.in_buffer = &dummyBuf;
    private_cmd.in_buffer_len = sizeof(dummyBuf);
    private_cmd.out_buffer = NULL;
    private_cmd.out_buffer_len = 0;

    strncpy(wrq.ifr_name, iface, sizeof(wrq.ifr_name));
    wrq.u.data.length = sizeof(ti_private_cmd_t);
    wrq.u.data.pointer = &private_cmd;
    wrq.u.data.flags = 0;
    ret = ioctl(mSock, SIOCIWFIRSTPRIV, &wrq);
    usleep(AP_DRIVER_START_DELAY);
    LOGD("Softap driver start: %d", ret);
    return ret;
}

int SoftapController::stopDriver(char *iface) {
    struct iwreq wrq;
    ti_private_cmd_t private_cmd;

    int ret, dummyBuf;

    if (mSock < 0) {
        LOGE("Softap driver stop - failed to open socket");
        return -1;
    }
    if (!iface || (iface[0] == '\0')) {
        LOGD("Softap driver stop - wrong interface");
        return -1;
    }

    private_cmd.cmd = DRIVER_STOP_PARAM;
    private_cmd.flags = PRIVATE_CMD_SET_FLAG;
    private_cmd.in_buffer = &dummyBuf;
    private_cmd.in_buffer_len = sizeof(dummyBuf);
    private_cmd.out_buffer = NULL;
    private_cmd.out_buffer_len = 0;

    strncpy(wrq.ifr_name, iface, sizeof(wrq.ifr_name));
    wrq.u.data.length = sizeof(ti_private_cmd_t);
    wrq.u.data.pointer = &private_cmd;
    wrq.u.data.flags = 0;
    ret = ioctl(mSock, SIOCIWFIRSTPRIV, &wrq);
    LOGD("Softap driver stop: %d", ret);
    return ret;
}

int SoftapController::startSoftap() {
    int i, ret = 0;
    THostapdCLICmd cmd;

    if(mPid == 1) {
        LOGE("Softap already started");
        return 0;
    }

    if (property_set("ctl.start", "hostapd") < 0) {
        LOGE("Failed to start hostapd");
        return -1; 
    }

    cmd.eCmdType = HOSTAPD_CLI_CMD_PING;

    for(i=0; i < HOSTAPD_MAX_RETRIES; i++) {
        usleep(AP_BSS_START_DELAY);
        ret = HostapdCLI_RunCommand("tiap0", &cmd);
        if(ret == -1) {
            continue;
        } else {
            LOGD("Softap startap - Ok");
            mPid = 1;
            return 0;
        }
    }

    acquire_wake_lock(PARTIAL_WAKE_LOCK,"hotspot_wake_lock");

    return ret;
}

int SoftapController::stopSoftap() {
    int ret = 0;

    if (mPid == 0) {
        LOGE("Softap already stopped");
        return 0;
    }

    if (property_set("ctl.stop", "hostapd") < 0) {
        LOGE("Failed to stop hostapd");
        return -1;
    }

    mPid = 0;
    usleep(AP_BSS_STOP_DELAY);

    release_wake_lock("hotspot_wake_lock");

    return ret;
}

bool SoftapController::isSoftapStarted() {
    return (mPid != 0 ? true : false);
}

/*
 * Arguments:
 *      argv[2] - wlan interface
 *      argv[3] - softap interface
 *      argv[4] - SSID
 *	argv[5] - Security
 *	argv[6] - Key
 *	argv[7] - Channel
 *	argv[8] - Preamble
 *	argv[9] - Max SCB
 */
int SoftapController::setSoftap(int argc, char *argv[]) {
    int ret = 0;
    THostapdCLICmd cmd;
    char buf[128];
    char newSSID[128];
    char newWPA[1024];

    LOGD("%s - %s - %s - %s - %s - %s",argv[2],argv[3],argv[4],argv[5],argv[6],argv[7]);

    if (mPid == 0) {
        LOGE("Softap set - hostapd not started");
        return -1;
    }
    if (argc < 4) {
        LOGE("Softap set - missing arguments");
        return -1;
    }

    FILE* fp = fopen("/system/etc/wifi/softap/hostapd.conf", "r");
    if (!fp) {
       LOGE("Softap set - hostapd temp file read failed");
       return -1; 
    }

    FILE* fp2 = fopen("/data/misc/wifi/hostapd.conf", "w");
    if (!fp2) {
       LOGE("Softap set - hostapd.conf file read failed");
       fclose(fp);
       return -1;
    }

    while (fgets(buf, sizeof(buf), fp)) {
        if((strncmp(buf,"ssid=",5) == 0) ||
           (strncmp(buf,"wpa=",4) == 0) ||
           (strncmp(buf,"wpa_passphrase=",15) == 0) ||
           (strncmp(buf,"wpa_key_mgmt=",12) == 0) ||
           (strncmp(buf,"wpa_pairwise=",12) == 0) ||
           (strncmp(buf,"rsn_pairwise=",12) == 0)) {
           continue;
        }
        fputs(buf,fp2);
    }

    // Update SSID
    sprintf(newSSID,"ssid=%s\n",argv[4]);
    fputs(newSSID,fp2);

    // Update security
    if(strncmp(argv[5],"open",4) != 0) {
        sprintf(newWPA,"wpa=2\nwpa_passphrase=%s\nwpa_key_mgmt=WPA-PSK\nwpa_pairwise=CCMP\nrsn_pairwise=CCMP\n",argv[6]);
        fputs(newWPA,fp2);
    }

    fclose(fp);
    fclose(fp2);

    cmd.eCmdType = HOSTAPD_CLI_CMD_RESET;
    ret = HostapdCLI_RunCommand(argv[3], &cmd);
 
    if (ret == -1) {
        LOGE("Softap set - failed: %d", ret);
    }
    else {
        LOGD("Softap set - Ok");
        usleep(AP_SET_CFG_DELAY);
    }

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
