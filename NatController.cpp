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

#define LOG_TAG "NatController"
#include <cutils/log.h>

#include "NatController.h"

extern "C" int logwrap(int argc, const char **argv, int background);

static char IPTABLES_PATH[] = "/system/bin/iptables";

NatController::NatController() {
    natCount = 0;
}

NatController::~NatController() {
}

int NatController::runIptablesCmd(const char *cmd) {
    char buffer[255];

    strncpy(buffer, cmd, sizeof(buffer)-1);

    const char *args[16];
    char *next = buffer;
    char *tmp;

    args[0] = IPTABLES_PATH;
    args[1] = "--verbose";
    int i = 2;

    while ((tmp = strsep(&next, " "))) {
        args[i++] = tmp;
        if (i == 16) {
            LOGE("iptables argument overflow");
            errno = E2BIG;
            return -1;
        }
    }
    args[i] = NULL;

    return logwrap(i, args, 0);
}

int NatController::setDefaults() {

    if (runIptablesCmd("-P INPUT ACCEPT"))
        return -1;
    if (runIptablesCmd("-F INPUT"))
        return -1;
    if (runIptablesCmd("-P OUTPUT ACCEPT"))
        return -1;
    if (runIptablesCmd("-F OUTPUT"))
        return -1;
    if (runIptablesCmd("-P FORWARD DROP"))
        return -1;
    if (runIptablesCmd("-F FORWARD"))
        return -1;
    if (runIptablesCmd("-t nat -F"))
        return -1;
    return 0;
}

bool NatController::interfaceExists(const char *iface) {
    // XXX: STOPSHIP - Implement this
    return true;
}

int NatController::doNatCommands(const char *intIface, const char *extIface, bool add) {
    char cmd[255];

    // handle decrement to 0 case (do reset to defaults) and erroneous dec below 0
    if (add == false) {
        if (natCount <= 1) {
            int ret = setDefaults();
            if (ret == 0) {
                natCount=0;
            }
            return ret;
        }
    }

    if (!interfaceExists(intIface) || !interfaceExists (extIface)) {
        LOGE("Invalid interface specified");
        errno = ENODEV;
        return -1;
    }

    snprintf(cmd, sizeof(cmd),
             "-%s FORWARD -i %s -o %s -m state --state ESTABLISHED,RELATED -j ACCEPT",
             (add ? "A" : "D"),
             extIface, intIface);
    if (runIptablesCmd(cmd)) {
        return -1;
    }

    snprintf(cmd, sizeof(cmd), "-%s FORWARD -i %s -o %s -j ACCEPT", (add ? "A" : "D"),
            intIface, extIface);
    if (runIptablesCmd(cmd)) {
        // unwind what's been done, but don't care about success - what more could we do?
        snprintf(cmd, sizeof(cmd),
                 "-%s FORWARD -i %s -o %s -m state --state ESTABLISHED,RELATED -j ACCEPT",
                 (!add ? "A" : "D"),
                 extIface, intIface);
        return -1;
    }

    // add this if we are the first added nat
    if (add && natCount == 0) {
        snprintf(cmd, sizeof(cmd), "-t nat -A POSTROUTING -o %s -j MASQUERADE", extIface);
        if (runIptablesCmd(cmd)) {
            // unwind what's been done, but don't care about success - what more could we do?
            setDefaults();;
            return -1;
        }
    }

    if (add) {
        natCount++;
    } else {
        natCount--;
    }
    return 0;
}

int NatController::enableNat(const char *intIface, const char *extIface) {
    return doNatCommands(intIface, extIface, true);
}

int NatController::disableNat(const char *intIface, const char *extIface) {
    return doNatCommands(intIface, extIface, false);
}
