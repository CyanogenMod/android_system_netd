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
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <cutils/properties.h>

#define LOG_TAG "NatController"
#include <cutils/log.h>

#include "NatController.h"
#include "SecondaryTableController.h"
#include "oem_iptables_hook.h"
#include "NetdConstants.h"

extern "C" int system_nosh(const char *command);

NatController::NatController(SecondaryTableController *ctrl) {
    secondaryTableCtrl = ctrl;
    setDefaults();
}

NatController::~NatController() {
}

int NatController::runCmd(const char *path, const char *cmd) {
    char *buffer;
    size_t len = strnlen(cmd, 255);
    int res;

    if (len == 255) {
        ALOGE("command too long");
        errno = E2BIG;
        return -1;
    }

    asprintf(&buffer, "%s %s", path, cmd);
    res = system_nosh(buffer);
    free(buffer);
    return res;
}

int NatController::setDefaults() {

    if (runCmd(IPTABLES_PATH, "-P INPUT ACCEPT"))
        return -1;
    if (runCmd(IPTABLES_PATH, "-P OUTPUT ACCEPT"))
        return -1;
    if (runCmd(IPTABLES_PATH, "-P FORWARD DROP"))
        return -1;
    if (runCmd(IPTABLES_PATH, "-F FORWARD"))
        return -1;
    if (runCmd(IPTABLES_PATH, "-t nat -F"))
        return -1;

    runCmd(IP_PATH, "rule flush");
    runCmd(IP_PATH, "-6 rule flush");
    runCmd(IP_PATH, "rule add from all lookup default prio 32767");
    runCmd(IP_PATH, "rule add from all lookup main prio 32766");
    runCmd(IP_PATH, "-6 rule add from all lookup default prio 32767");
    runCmd(IP_PATH, "-6 rule add from all lookup main prio 32766");
    runCmd(IP_PATH, "route flush cache");

    natCount = 0;

    setupOemIptablesHook();
    return 0;
}

bool NatController::checkInterface(const char *iface) {
    if (strlen(iface) > MAX_IFACE_LENGTH) return false;
    return true;
}

//  0    1       2       3       4            5
// nat enable intface extface addrcnt nated-ipaddr/prelength
int NatController::enableNat(const int argc, char **argv) {
    char cmd[255];
    int i;
    int addrCount = atoi(argv[4]);
    int ret = 0;
    const char *intIface = argv[2];
    const char *extIface = argv[3];
    int tableNumber;

    if (!checkInterface(intIface) || !checkInterface(extIface)) {
        ALOGE("Invalid interface specified");
        errno = ENODEV;
        return -1;
    }

    if (argc < 5 + addrCount) {
        ALOGE("Missing Argument");
        errno = EINVAL;
        return -1;
    }

    tableNumber = secondaryTableCtrl->findTableNumber(extIface);
    if (tableNumber != -1) {
        for(i = 0; i < addrCount; i++) {
            ret |= secondaryTableCtrl->modifyFromRule(tableNumber, ADD, argv[5+i]);

            ret |= secondaryTableCtrl->modifyLocalRoute(tableNumber, ADD, intIface, argv[5+i]);
        }
        runCmd(IP_PATH, "route flush cache");
    }

    if (ret != 0 || setForwardRules(true, intIface, extIface) != 0) {
        if (tableNumber != -1) {
            for (i = 0; i < addrCount; i++) {
                secondaryTableCtrl->modifyLocalRoute(tableNumber, DEL, intIface, argv[5+i]);

                secondaryTableCtrl->modifyFromRule(tableNumber, DEL, argv[5+i]);
            }
            runCmd(IP_PATH, "route flush cache");
        }
        ALOGE("Error setting forward rules");
        errno = ENODEV;
        return -1;
    }

    natCount++;
    // add this if we are the first added nat
    if (natCount == 1) {
        snprintf(cmd, sizeof(cmd), "-t nat -A POSTROUTING -o %s -j MASQUERADE", extIface);
        if (runCmd(IPTABLES_PATH, cmd)) {
            ALOGE("Error seting postroute rule: %s", cmd);
            // unwind what's been done, but don't care about success - what more could we do?
            for (i = 0; i < addrCount; i++) {
                secondaryTableCtrl->modifyLocalRoute(tableNumber, DEL, intIface, argv[5+i]);

                secondaryTableCtrl->modifyFromRule(tableNumber, DEL, argv[5+i]);
            }
            setDefaults();
            return -1;
        }
    }

    return 0;
}

int NatController::setForwardRules(bool add, const char *intIface, const char * extIface) {
    char cmd[255];

    snprintf(cmd, sizeof(cmd),
             "-%s FORWARD -i %s -o %s -m state --state ESTABLISHED,RELATED -j ACCEPT",
             (add ? "A" : "D"),
             extIface, intIface);
    if (runCmd(IPTABLES_PATH, cmd) && add) {
        return -1;
    }

    snprintf(cmd, sizeof(cmd),
            "-%s FORWARD -i %s -o %s -m state --state INVALID -j DROP",
            (add ? "A" : "D"),
            intIface, extIface);
    if (runCmd(IPTABLES_PATH, cmd) && add) {
        // bail on error, but only if adding
        snprintf(cmd, sizeof(cmd),
                "-%s FORWARD -i %s -o %s -m state --state ESTABLISHED,RELATED -j ACCEPT",
                (!add ? "A" : "D"),
                extIface, intIface);
        runCmd(IPTABLES_PATH, cmd);
        return -1;
    }

    snprintf(cmd, sizeof(cmd), "-%s FORWARD -i %s -o %s -j ACCEPT", (add ? "A" : "D"),
            intIface, extIface);
    if (runCmd(IPTABLES_PATH, cmd) && add) {
        // unwind what's been done, but don't care about success - what more could we do?
        snprintf(cmd, sizeof(cmd),
                "-%s FORWARD -i %s -o %s -m state --state INVALID -j DROP",
                (!add ? "A" : "D"),
                intIface, extIface);
        runCmd(IPTABLES_PATH, cmd);

        snprintf(cmd, sizeof(cmd),
                 "-%s FORWARD -i %s -o %s -m state --state ESTABLISHED,RELATED -j ACCEPT",
                 (!add ? "A" : "D"),
                 extIface, intIface);
        runCmd(IPTABLES_PATH, cmd);
        return -1;
    }
    return 0;
}

// nat disable intface extface
//  0    1       2       3       4            5
// nat enable intface extface addrcnt nated-ipaddr/prelength
int NatController::disableNat(const int argc, char **argv) {
    char cmd[255];
    int i;
    int addrCount = atoi(argv[4]);
    const char *intIface = argv[2];
    const char *extIface = argv[3];
    int tableNumber;

    if (!checkInterface(intIface) || !checkInterface(extIface)) {
        ALOGE("Invalid interface specified");
        errno = ENODEV;
        return -1;
    }

    if (argc < 5 + addrCount) {
        ALOGE("Missing Argument");
        errno = EINVAL;
        return -1;
    }

    setForwardRules(false, intIface, extIface);

    tableNumber = secondaryTableCtrl->findTableNumber(extIface);
    if (tableNumber != -1) {
        for (i = 0; i < addrCount; i++) {
            secondaryTableCtrl->modifyLocalRoute(tableNumber, DEL, intIface, argv[5+i]);

            secondaryTableCtrl->modifyFromRule(tableNumber, DEL, argv[5+i]);
        }

        runCmd(IP_PATH, "route flush cache");
    }

    if (--natCount <= 0) {
        // handle decrement to 0 case (do reset to defaults) and erroneous dec below 0
        setDefaults();
    }
    return 0;
}
