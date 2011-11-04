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
#include <string.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#define LOG_TAG "SecondaryTablController"
#include <cutils/log.h>
#include <cutils/properties.h>

#include "ResponseCode.h"
#include "SecondaryTableController.h"

static char IP_PATH[] = "/system/bin/ip";

SecondaryTableController::SecondaryTableController() {
    int i;
    for (i=0; i < INTERFACES_TRACKED; i++) {
        mInterfaceTable[i][0] = 0;
        // TODO - use a hashtable or other prebuilt container class
        mInterfaceRuleCount[i] = 0;
    }
}

SecondaryTableController::~SecondaryTableController() {
}

int SecondaryTableController::findTableNumber(const char *iface) {
    int i;
    for (i = 0; i < INTERFACES_TRACKED; i++) {
        if (strncmp(iface, mInterfaceTable[i], MAX_IFACE_LENGTH) == 0) {
            return i;
        }
    }
    return -1;
}

int SecondaryTableController::addRoute(SocketClient *cli, char *iface, char *dest, int prefix,
        char *gateway) {
    char *cmd;

    int tableIndex = findTableNumber(iface);
    if (tableIndex == -1) {
        tableIndex = findTableNumber(""); // look for an empty slot
        if (tableIndex == -1) {
            LOGE("Max number of NATed interfaces reached");
            errno = ENODEV;
            cli->sendMsg(ResponseCode::OperationFailed, "Max number NATed", true);
            return -1;
        }
        strncpy(mInterfaceTable[tableIndex], iface, MAX_IFACE_LENGTH);
    }

    asprintf(&cmd, "%s route add %s/%d via %s table %d",
            IP_PATH, dest, prefix, gateway, tableIndex+BASE_TABLE_NUMBER);
    if (runAndFree(cli, cmd)) {
        LOGE("ip route add failed: %s", cmd);
        errno = ENODEV;
        cli->sendMsg(ResponseCode::OperationFailed, "ip route add failed", true);
        return -1;
    }
    mInterfaceRuleCount[tableIndex]++;
    cli->sendMsg(ResponseCode::CommandOkay, "Route added", false);
    return 0;
}

int SecondaryTableController::removeRoute(SocketClient *cli, char *iface, char *dest, int prefix,
        char *gateway) {
    char *cmd;
    int tableIndex = findTableNumber(iface);
    if (tableIndex == -1) {
        LOGE("Interface not found");
        errno = ENODEV;
        cli->sendMsg(ResponseCode::OperationFailed, "Interface not found", true);
        return -1;
    }

    asprintf(&cmd, "%s route del %s/%d via %s table %d",
            IP_PATH, dest, prefix, gateway, tableIndex+BASE_TABLE_NUMBER);
    if (runAndFree(cli, cmd)) {
        LOGE("ip route del failed");
        errno = ENODEV;
        cli->sendMsg(ResponseCode::OperationFailed, "ip route del failed", true);
        return -1;
    }
    if (--mInterfaceRuleCount[tableIndex]<1) {
        mInterfaceTable[tableIndex][0]=0;
    }
    cli->sendMsg(ResponseCode::CommandOkay, "Route removed", false);
    return 0;
}

int SecondaryTableController::runAndFree(SocketClient *cli, char *cmd) {
    int ret = 0;
    if (strlen(cmd) >= 255) {
        LOGE("ip command (%s) too long", cmd);
        errno = E2BIG;
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Too long", true);
        free(cmd);
        return -1;
    }
    ret = system(cmd);
    free(cmd);
    return ret;
}
