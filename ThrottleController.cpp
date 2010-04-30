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
extern "C" int ifc_init(void);
extern "C" int ifc_up(const char *name);
extern "C" int ifc_down(const char *name);

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
    char cmd[512];
    char ifn[65];
    int rc;

    memset(ifn, 0, sizeof(ifn));
    strncpy(ifn, iface, sizeof(ifn)-1);

    if (txKbps == -1) {
        reset(ifn);
        return 0;
    }

    /*
     *
     * Target interface configuration
     *
     */

    /*
     * Add root qdisc for the interface
     */
    sprintf(cmd, "qdisc add dev %s root handle 1: htb default 1 r2q 1000", ifn);
    if (runTcCmd(cmd)) {
        LOGE("Failed to add root qdisc (%s)", strerror(errno));
        goto fail;
    }

    /*
     * Add our egress throttling class
     */
    sprintf(cmd, "class add dev %s parent 1: classid 1:1 htb rate %dkbit", ifn, txKbps);
    if (runTcCmd(cmd)) {
        LOGE("Failed to add egress throttling class (%s)", strerror(errno));
        goto fail;
    }

    /*
     * Bring up the IFD device
     */
    ifc_init();
    if (ifc_up("ifb0")) {
        LOGE("Failed to up ifb0 (%s)", strerror(errno));
        goto fail;
    }

    /*
     * Add root qdisc for IFD
     */
    sprintf(cmd, "qdisc add dev ifb0 root handle 1: htb default 1 r2q 1000");
    if (runTcCmd(cmd)) {
        LOGE("Failed to add root ifb qdisc (%s)", strerror(errno));
        goto fail;
    }

    /*
     * Add our ingress throttling class
     */
    sprintf(cmd, "class add dev ifb0 parent 1: classid 1:1 htb rate %dkbit", rxKbps);
    if (runTcCmd(cmd)) {
        LOGE("Failed to add ingress throttling class (%s)", strerror(errno));
        goto fail;
    }

    /*
     * Add ingress qdisc for pkt redirection
     */
    sprintf(cmd, "qdisc add dev %s ingress", ifn);
    if (runTcCmd(cmd)) {
        LOGE("Failed to add ingress qdisc (%s)", strerror(errno));
        goto fail;
    }

    /*
     * Add filter to link <ifn> -> ifb0
     */
    sprintf(cmd, "filter add dev %s parent ffff: protocol ip prio 10 u32 match "
            "u32 0 0 flowid 1:1 action mirred egress redirect dev ifb0", ifn);
    if (runTcCmd(cmd)) {
        LOGE("Failed to add ifb filter (%s)", strerror(errno));
        goto fail;
    }

    return 0;
fail:
    reset(ifn);
    return -1;
}

void ThrottleController::reset(const char *iface) {
    char cmd[128];

    sprintf(cmd, "qdisc del dev %s root", iface);
    runTcCmd(cmd);
    sprintf(cmd, "qdisc del dev %s ingress", iface);
    runTcCmd(cmd);

    runTcCmd("qdisc del dev ifb0 root");
}

int ThrottleController::getInterfaceRxThrottle(const char *iface, int *rx) {
    *rx = 0;
    return 0;
}

int ThrottleController::getInterfaceTxThrottle(const char *iface, int *tx) {
    *tx = 0;
    return 0;
}
