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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#define LOG_TAG "OemIptablesHook"
#include <cutils/log.h>

extern "C" int system_nosh(const char *command);

static char IPTABLES_PATH[] = "/system/bin/iptables";
static char OEM_SCRIPT_PATH[] = "/system/bin/oem-iptables-init.sh";

static int runIptablesCmd(const char *cmd) {
    char *buffer;
    size_t len = strnlen(cmd, 255);
    int res;

    if (len == 255) {
        LOGE("command too long");
        return -1;
    }

    asprintf(&buffer, "%s %s", IPTABLES_PATH, cmd);
    res = system_nosh(buffer);
    free(buffer);
    return res;
}

static bool oemSetupHooks() {
    // Order is important!
    // -N to create the chain (no-op if already exist).
    // -D to delete any pre-existing jump rule, to prevent dupes (no-op if doesn't exist)
    // -I to insert our jump rule into the default chain

    runIptablesCmd("-N oem_out");
    runIptablesCmd("-D OUTPUT -j oem_out");
    if (runIptablesCmd("-I OUTPUT -j oem_out"))
        return false;

    runIptablesCmd("-N oem_fwd");
    runIptablesCmd("-D FORWARD -j oem_fwd");
    if (runIptablesCmd("-I FORWARD -j oem_fwd"))
        return false;

    runIptablesCmd("-t nat -N oem_nat_pre");
    runIptablesCmd("-t nat -D PREROUTING -j oem_nat_pre");
    if (runIptablesCmd("-t nat -I PREROUTING -j oem_nat_pre"))
        return false;

    return true;
}

static bool oemCleanupHooks() {
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

    return true;
}

static bool oemInitChains() {
    int ret = system(OEM_SCRIPT_PATH);
    if ((-1 == ret) || (0 != WEXITSTATUS(ret))) {
        LOGE("%s failed: %s", OEM_SCRIPT_PATH, strerror(errno));
        oemCleanupHooks();
        return false;
    }
    return true;
}


void setupOemIptablesHook() {
    if (0 == access(OEM_SCRIPT_PATH, R_OK | X_OK)) {
        // The call to oemCleanupHooks() is superfluous when done on bootup,
        // but is needed for the case where netd has crashed/stopped and is
        // restarted.
        if (oemCleanupHooks() && oemSetupHooks() && oemInitChains()) {
            LOGI("OEM iptable hook installed.");
        }
    }
}
