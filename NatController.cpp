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
#include <sys/wait.h>
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
static char OEM_SCRIPT_PATH[] = "/system/bin/oem-iptables-init.sh";

NatController::NatController() : mOemChainsExist(false) {
    natCount = 0;

    setDefaults();

    if (0 == access(OEM_SCRIPT_PATH, R_OK | X_OK)) {
        // The call to oemCleanupHooks() is superfluous when done on bootup,
        // but is needed for the case where netd has crashed/stopped and is
        // restarted.
        if (!oemCleanupHooks() && !oemSetupHooks() && !oemInitChains()) {
            mOemChainsExist = true;
        }
    }
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
    if (runIptablesCmd("-P OUTPUT ACCEPT"))
        return -1;
    if (runIptablesCmd("-P FORWARD DROP"))
        return -1;
    if (runIptablesCmd("-F FORWARD"))
        return -1;

    if (runIptablesCmd("-t nat -F PREROUTING"))
        return -1;
    if (runIptablesCmd("-t nat -F OUTPUT"))
        return -1;
    if (runIptablesCmd("-t nat -F POSTROUTING"))
        return -1;

    return 0;
}

int NatController::oemSetupHooks() {
    // Order is important!
    // -N to create the chain (no-op if already exist).
    // -D to delete any pre-existing jump rule, to prevent dupes (no-op if doesn't exist)
    // -I to insert our jump rule into the default chain

    runIptablesCmd("-N oem_out");
    runIptablesCmd("-D OUTPUT -j oem_out");
    if (runIptablesCmd("-I OUTPUT -j oem_out"))
        return -1;

    runIptablesCmd("-N oem_fwd");
    runIptablesCmd("-D FORWARD -j oem_fwd");
    if (runIptablesCmd("-I FORWARD -j oem_fwd"))
        return -1;

    runIptablesCmd("-t nat -N oem_nat_pre");
    runIptablesCmd("-t nat -D PREROUTING -j oem_nat_pre");
    if (runIptablesCmd("-t nat -I PREROUTING -j oem_nat_pre"))
        return -1;

    return 0;
}

int NatController::oemCleanupHooks() {
    // Order is important!
    // -D to remove ref to the chain
    // -F to empty the chain
    // -X to delete the chain

    runIptablesCmd("-D OUTPUT -j oem_out");
    runIptablesCmd("-F oem_out");
    runIptablesCmd("-X oem_out");

    runIptablesCmd("-D FORWARD -j oem_fwd");
    runIptablesCmd("-F oem_fwd");
    runIptablesCmd("-X oem_fwd");

    runIptablesCmd("-t nat -D PREROUTING -j oem_nat_pre");
    runIptablesCmd("-t nat -F oem_nat_pre");
    runIptablesCmd("-t nat -X oem_nat_pre");

    return 0;
}

// This method should only be called when netd starts up.  The OEM chains are
// intended to be static, so there's no need to flush and recreate them every
// time setDefaults() is called.
int NatController::oemInitChains() {
    int ret = system(OEM_SCRIPT_PATH);
    if ((-1 == ret) || (0 != WEXITSTATUS(ret))) {
        LOGE("%s failed: %s", OEM_SCRIPT_PATH, strerror(errno));
        return -1;
    }
    return 0;
}

bool NatController::interfaceExists(const char *iface) {
    // XXX: Implement this
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
            if (mOemChainsExist)
                oemSetupHooks();
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

    snprintf(cmd, sizeof(cmd),
            "-%s FORWARD -i %s -o %s -m state --state INVALID -j DROP",
            (add ? "A" : "D"),
            intIface, extIface);
    if (runIptablesCmd(cmd)) {
        snprintf(cmd, sizeof(cmd),
                "-%s FORWARD -i %s -o %s -m state --state ESTABLISHED,RELATED -j ACCEPT",
                (!add ? "A" : "D"),
                extIface, intIface);
        runIptablesCmd(cmd);
        return -1;
    }

    snprintf(cmd, sizeof(cmd), "-%s FORWARD -i %s -o %s -j ACCEPT", (add ? "A" : "D"),
            intIface, extIface);
    if (runIptablesCmd(cmd)) {
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
            // unwind what's been done, but don't care about success - what more could we do?
            setDefaults();;
            oemSetupHooks();
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
