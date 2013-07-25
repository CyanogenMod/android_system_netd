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
#include <logwrap/logwrap.h>

#include "ResponseCode.h"
#include "NetdConstants.h"
#include "SecondaryTableController.h"

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
        // compare through the final null, hence +1
        if (strncmp(iface, mInterfaceTable[i], IFNAMSIZ + 1) == 0) {
            return i;
        }
    }
    return -1;
}

int SecondaryTableController::addRoute(SocketClient *cli, char *iface, char *dest, int prefix,
        char *gateway) {
    int tableIndex = findTableNumber(iface);
    if (tableIndex == -1) {
        tableIndex = findTableNumber(""); // look for an empty slot
        if (tableIndex == -1) {
            ALOGE("Max number of NATed interfaces reached");
            errno = ENODEV;
            cli->sendMsg(ResponseCode::OperationFailed, "Max number NATed", true);
            return -1;
        }
        strncpy(mInterfaceTable[tableIndex], iface, IFNAMSIZ);
        // Ensure null termination even if truncation happened
        mInterfaceTable[tableIndex][IFNAMSIZ] = 0;
    }

    return modifyRoute(cli, ADD, iface, dest, prefix, gateway, tableIndex);
}

int SecondaryTableController::modifyRoute(SocketClient *cli, const char *action, char *iface,
        char *dest, int prefix, char *gateway, int tableIndex) {
    char dest_str[44]; // enough to store an IPv6 address + 3 character bitmask
    char tableIndex_str[11];
    int ret;

    //  IP tool doesn't like "::" - the equiv of 0.0.0.0 that it accepts for ipv4
    snprintf(dest_str, sizeof(dest_str), "%s/%d", dest, prefix);
    snprintf(tableIndex_str, sizeof(tableIndex_str), "%d", tableIndex + BASE_TABLE_NUMBER);

    if (strcmp("::", gateway) == 0) {
        const char *cmd[] = {
                IP_PATH,
                "route",
                action,
                dest_str,
                "dev",
                iface,
                "table",
                tableIndex_str
        };
        ret = runCmd(ARRAY_SIZE(cmd), cmd);
    } else {
        const char *cmd[] = {
                IP_PATH,
                "route",
                action,
                dest_str,
                "via",
                gateway,
                "dev",
                iface,
                "table",
                tableIndex_str
        };
        ret = runCmd(ARRAY_SIZE(cmd), cmd);
    }

    if (ret) {
        ALOGE("ip route %s failed: %s route %s %s/%d via %s dev %s table %d", action,
                IP_PATH, action, dest, prefix, gateway, iface, tableIndex+BASE_TABLE_NUMBER);
        errno = ENODEV;
        cli->sendMsg(ResponseCode::OperationFailed, "ip route modification failed", true);
        return -1;
    }

    if (strcmp(action, ADD) == 0) {
        mInterfaceRuleCount[tableIndex]++;
    } else {
        if (--mInterfaceRuleCount[tableIndex] < 1) {
            mInterfaceRuleCount[tableIndex] = 0;
            mInterfaceTable[tableIndex][0] = 0;
        }
    }
    modifyRuleCount(tableIndex, action);
    cli->sendMsg(ResponseCode::CommandOkay, "Route modified", false);
    return 0;
}

void SecondaryTableController::modifyRuleCount(int tableIndex, const char *action) {
    if (strcmp(action, ADD) == 0) {
        mInterfaceRuleCount[tableIndex]++;
    } else {
        if (--mInterfaceRuleCount[tableIndex] < 1) {
            mInterfaceRuleCount[tableIndex] = 0;
            mInterfaceTable[tableIndex][0] = 0;
        }
    }
}

int SecondaryTableController::verifyTableIndex(int tableIndex) {
    if ((tableIndex < 0) ||
            (tableIndex >= INTERFACES_TRACKED) ||
            (mInterfaceTable[tableIndex][0] == 0)) {
        return -1;
    } else {
        return 0;
    }
}

const char *SecondaryTableController::getVersion(const char *addr) {
    if (strchr(addr, ':') != NULL) {
        return "-6";
    } else {
        return "-4";
    }
}

int SecondaryTableController::removeRoute(SocketClient *cli, char *iface, char *dest, int prefix,
        char *gateway) {
    int tableIndex = findTableNumber(iface);
    if (tableIndex == -1) {
        ALOGE("Interface not found");
        errno = ENODEV;
        cli->sendMsg(ResponseCode::OperationFailed, "Interface not found", true);
        return -1;
    }

    return modifyRoute(cli, DEL, iface, dest, prefix, gateway, tableIndex);
}

int SecondaryTableController::modifyFromRule(int tableIndex, const char *action,
        const char *addr) {
    char tableIndex_str[11];

    if (verifyTableIndex(tableIndex)) {
        return -1;
    }

    snprintf(tableIndex_str, sizeof(tableIndex_str), "%d", tableIndex +
            BASE_TABLE_NUMBER);
    const char *cmd[] = {
            IP_PATH,
            getVersion(addr),
            "rule",
            action,
            "from",
            addr,
            "table",
            tableIndex_str
    };
    if (runCmd(ARRAY_SIZE(cmd), cmd)) {
        return -1;
    }

    modifyRuleCount(tableIndex, action);
    return 0;
}

int SecondaryTableController::modifyLocalRoute(int tableIndex, const char *action,
        const char *iface, const char *addr) {
    char tableIndex_str[11];

    if (verifyTableIndex(tableIndex)) {
        return -1;
    }

    modifyRuleCount(tableIndex, action); // some del's will fail as the iface is already gone.

    snprintf(tableIndex_str, sizeof(tableIndex_str), "%d", tableIndex +
            BASE_TABLE_NUMBER);
    const char *cmd[] = {
            IP_PATH,
            "route",
            action,
            addr,
            "dev",
            iface,
            "table",
            tableIndex_str
    };

    return runCmd(ARRAY_SIZE(cmd), cmd);
}

int SecondaryTableController::runCmd(int argc, const char **argv) {
    int ret = 0;

    ret = android_fork_execvp(argc, (char **)argv, NULL, false, false);
    return ret;
}
