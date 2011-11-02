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

extern "C" int logwrap(int argc, const char **argv, int background);

static char IPTABLES_PATH[] = "/system/bin/iptables";

NatController::NatController() {
    natCount = 0;
}

NatController::~NatController() {
}

int NatController::runIptablesCmd(const char *cmd) {
    char *buffer;
    size_t len = strnlen(cmd, 255);
    int res;

    if (len == 255) {
        LOGE("iptables command too long");
        errno = E2BIG;
        return -1;
    }

    asprintf(&buffer, "%s %s", IPTABLES_PATH, cmd);
    res = system(buffer);
    free(buffer);
    return res;
}

int NatController::setDefaults() {

    if (runIptablesCmd("-P INPUT ACCEPT"))
        return -1;
    if (runIptablesCmd("-P OUTPUT ACCEPT"))
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
    // XXX: Implement this
    return true;
}

// when un-doing NAT, we should report errors, but also try to do as much cleanup
// as we can - don't short circuit on error.
int NatController::doNatCommands(const char *intIface, const char *extIface, bool add) {
    char cmd[255];

    char bootmode[PROPERTY_VALUE_MAX] = {0};
    property_get("ro.bootmode", bootmode, "unknown");
    if (0 != strcmp("bp-tools", bootmode)) {
        // handle decrement to 0 case (do reset to defaults) and erroneous dec below 0
        if (add == false) {
            if (natCount <= 1) {
                int ret = setDefaults();
                if (ret == 0) {
                    natCount=0;
                }
                LOGE("setDefaults returned %d", ret);
                return ret;
            }
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
    if (runIptablesCmd(cmd) && add) {
        // only bail out if we are adding, not removing nat rules
        return -1;
    }

    snprintf(cmd, sizeof(cmd),
            "-%s FORWARD -i %s -o %s -m state --state INVALID -j DROP",
            (add ? "A" : "D"),
            intIface, extIface);
    if (runIptablesCmd(cmd) && add) {
        // bail on error, but only if adding
        snprintf(cmd, sizeof(cmd),
                "-%s FORWARD -i %s -o %s -m state --state ESTABLISHED,RELATED -j ACCEPT",
                (!add ? "A" : "D"),
                extIface, intIface);
        runIptablesCmd(cmd);
        return -1;
    }

    snprintf(cmd, sizeof(cmd), "-%s FORWARD -i %s -o %s -j ACCEPT", (add ? "A" : "D"),
            intIface, extIface);
    if (runIptablesCmd(cmd) && add) {
        // unwind what's been done, but don't care about success - what more could we do?
        snprintf(cmd, sizeof(cmd),
                "-%s FORWARD -i %s -o %s -m state --state INVALID -j DROP",
                (!add ? "A" : "D"),
                intIface, extIface);
        runIptablesCmd(cmd);

        snprintf(cmd, sizeof(cmd),
                 "-%s FORWARD -i %s -o %s -m state --state ESTABLISHED,RELATED -j ACCEPT",
                 (!add ? "A" : "D"),
                 extIface, intIface);
        runIptablesCmd(cmd);
        return -1;
    }

    // add this if we are the first added nat
    if (add && natCount == 0) {
        snprintf(cmd, sizeof(cmd), "-t nat -A POSTROUTING -o %s -j MASQUERADE", extIface);
        if (runIptablesCmd(cmd)) {
            if (0 != strcmp("bp-tools", bootmode)) {
                // unwind what's been done, but don't care about success - what more could we do?
                setDefaults();;
            }
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
