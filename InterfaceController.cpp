/*
 * Copyright (C) 2012 The Android Open Source Project
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
#include <string.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#define LOG_TAG "InterfaceController"
#include <cutils/log.h>
#include <netutils/ifc.h>
#include <private/android_filesystem_config.h>

#include "InterfaceController.h"

InterfaceController::InterfaceController() {
    iSock = socket(AF_INET, SOCK_DGRAM, 0);
    if (iSock < 0)
        ALOGE("Failed to open socket");
    iBuf = (char *)malloc(INTERFACE_MAX_BUFFER_SIZE);
    if (!iBuf)
        ALOGE("Failed to allocate buffer");
}

InterfaceController::~InterfaceController() {
    if (iSock >= 0)
        close(iSock);
    if (iBuf)
        free(iBuf);
}

int InterfaceController::sendCommand(char *iface, char *cmd, char *buf, int buf_len) {
    struct ifreq ifr;
    android_wifi_priv_cmd priv_cmd;
    int ret;

    if (!iface || !cmd)
        return -1;

    memset(&ifr, 0, sizeof(ifr));
    memset(&priv_cmd, 0, sizeof(priv_cmd));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ);
    memcpy(buf, cmd, strlen(cmd) + 1);

    priv_cmd.buf = buf;
    priv_cmd.used_len = buf_len;
    priv_cmd.total_len = buf_len;
    ifr.ifr_data = &priv_cmd;

    if ((ret = ioctl(iSock, SIOCDEVPRIVATE + 1, &ifr)) < 0) {
        ALOGE("Failed to execute command: %s", cmd);
    } else {
        if (buf[0] == '\0') {
            snprintf(buf, buf_len, "OK");
        }
    }
    return ret;
}

/*
 * Arguments:
 *      argv[2] - wlan interface
 *      argv[3] - command
 *      argv[4] - argument
 *      rbuf    - returned buffer
 */
int InterfaceController::interfaceCommand(int argc, char *argv[], char **rbuf) {
    char cmd[INTERFACE_MAX_BUFFER_SIZE];
    unsigned int bc = 0;
    int ret;
    int i;

    if ((iSock < 0) || !iBuf || (argc < 4))
        return -1;

    for (i=3; i < argc; i++) {
        bc += snprintf(&cmd[bc], sizeof(cmd) - bc, "%s ", argv[i]);
    }
    if (bc >= sizeof(cmd))
        bc = sizeof(cmd) - 1;
    cmd[bc] = '\0';
    ret = sendCommand(argv[2], cmd, iBuf, INTERFACE_MAX_BUFFER_SIZE);
    if (rbuf)
        *rbuf = iBuf;
    return ret;
}
