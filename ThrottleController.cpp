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

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_sched.h>

#define LOG_TAG "ThrottleController"
#include <cutils/log.h>


#include "ThrottleController.h"

static char TC_PATH[] = "/system/bin/tc";

extern "C" int logwrap(int argc, const char **argv, int background);

int ThrottleController::runTcCmd(const char *cmd) {
    char buffer[255];

    strncpy(buffer, cmd, sizeof(buffer)-1);

    const char *args[32];
    char *next = buffer;
    char *tmp;

    args[0] = TC_PATH;
    int i = 1;

    while ((tmp = strsep(&next, " "))) {
        args[i++] = tmp;
        if (i == 32) {
            LOGE("tc argument overflow");
            errno = E2BIG;
            return -1;
        }
    }
    args[i] = NULL;

    return logwrap(i, args, 0);
}

int ThrottleController::setInterfaceThrottle(const char *iface, int rxKbps, int txKbps) {
    char *cmd;
    int rc;

    if (txKbps == -1) {
        reset(iface);
        return 0;
    }

    asprintf(&cmd, "qdisc add dev %s root handle 1: cbq avpkt 1000 bandwidth 10mbit", iface);
    rc = runTcCmd(cmd);
    free(cmd);
    if (rc) {
        LOGE("Failed to add cbq qdisc (%s)", strerror(errno));
        reset(iface);
        return -1;
    }

    asprintf(&cmd,
            "class add dev %s parent 1: classid 1:1 cbq rate %dkbit allot 1500 prio 5 bounded isolated",
                    iface, txKbps);
    rc = runTcCmd(cmd);
    free(cmd);
    if (rc) {
        LOGE("Failed to add class (%s)", strerror(errno));
        reset(iface);
        return -1;
    }

    asprintf(&cmd,
            "filter add dev %s parent 1: protocol ip prio 16 u32 match ip dst 0.0.0.0/0 flowid 1:1",
                    iface);
    rc = runTcCmd(cmd);
    free(cmd);
    if (runTcCmd(cmd)) {
        LOGE("Failed to add filter (%s)", strerror(errno));
        reset(iface);
        return -1;
    }

    return 0;
}

void ThrottleController::reset(const char *iface) {
    char *cmd;
    asprintf(&cmd, "qdisc del dev %s root", iface);
    runTcCmd(cmd);
    free(cmd);
}

int ThrottleController::getInterfaceRxThrottle(const char *iface, int *rx) {
    *rx = 0;
    return 0;
}

int ThrottleController::getInterfaceTxThrottle(const char *iface, int *tx) {
    *tx = 0;
    return 0;
}
