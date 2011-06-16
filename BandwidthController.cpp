/*
 * Copyright (C) 2011 The Android Open Source Project
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

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_sched.h>

#define LOG_TAG "BandwidthController"
#include <cutils/log.h>
#include <cutils/properties.h>

extern "C" int logwrap(int argc, const char **argv, int background);

#include "BandwidthController.h"


const int BandwidthController::MAX_CMD_LEN = 255;
const int BandwidthController::MAX_IFACENAME_LEN = 64;
const int BandwidthController::MAX_CMD_ARGS = 32;
const char BandwidthController::IPTABLES_PATH[] = "/system/bin/iptables";


/**
 * Some comments about the rules:
 *  * Ordering
 *    - when an interface is marked as costly it should be INSERTED into the INPUT/OUTPUT chains.
 *      E.g. "-I INPUT -i rmnet0 --goto costly"
 *    - quota'd rules in the costly chain should be before penalty_box lookups.
 *
 * * global quota vs per interface quota
 *   - global quota for all costly interfaces uses a single costly chain:
 *    . initial rules
 *      iptables -N costly
 *      iptables -I INPUT -i iface0 --goto costly
 *      iptables -I OUTPUT -o iface0 --goto costly
 *      iptables -I costly -m quota \! --quota 500000 --jump REJECT --reject-with icmp-net-prohibited
 *      iptables -A costly                            --jump penalty_box
 *      iptables -A costly -m owner --socket-exists
 *    . adding a new iface to this, E.g.:
 *      iptables -I INPUT -i iface1 --goto costly
 *      iptables -I OUTPUT -o iface1 --goto costly
 *
 *   - quota per interface. This is achieve by having "costly" chains per quota.
 *     E.g. adding a new costly interface iface0 with its own quota:
 *      iptables -N costly_iface0
 *      iptables -I INPUT -i iface0 --goto costly_iface0
 *      iptables -I OUTPUT -o iface0 --goto costly_iface0
 *      iptables -A costly_iface0 -m quota \! --quota 500000 --jump REJECT --reject-with icmp-net-prohibited
 *      iptables -A costly_iface0                            --jump penalty_box
 *      iptables -A costly_iface0 -m owner --socket-exists
 *
 * * penalty_box handling:
 *  - only one penalty_box for all interfaces
 *   E.g  Adding an app:
 *    iptables -A penalty_box -m owner --uid-owner app_3 --jump REJECT --reject-with icmp-net-prohibited
 */
const char *BandwidthController::cleanupCommands[] = {
    /* Cleanup rules. */
    "-F",
    "-t raw -F",
    "-X costly",
    "-X penalty_box",
};

const char *BandwidthController::setupCommands[] = {
    /* Created needed chains. */
    "-N costly",
    "-N penalty_box",
};

const char *BandwidthController::basicAccountingCommands[] = {
    "-F INPUT",
    "-A INPUT -i lo --jump ACCEPT",
    "-A INPUT -m owner --socket-exists",  /* This is a tracking rule. */

    "-F OUTPUT",
    "-A OUTPUT -o lo --jump ACCEPT",
    "-A OUTPUT -m owner --socket-exists",  /* This is a tracking rule. */

    "-F costly",
    "-A costly --jump penalty_box",
    "-A costly -m owner --socket-exists",    /* This is a tracking rule. */
    /* TODO(jpa): Figure out why iptables doesn't correctly return from this
     * chain. For now, hack the chain exit with an ACCEPT.
     */
    "-A costly --jump ACCEPT",
};


BandwidthController::BandwidthController(void) {

    char value[PROPERTY_VALUE_MAX];

    property_get("persist.bandwidth.enable", value, "0");
    if (!strcmp(value, "1")) {
        enableBandwidthControl();
    }

}

int BandwidthController::runIptablesCmd(const char *cmd) {
    char buffer[MAX_CMD_LEN];

    LOGD("About to run: iptables %s", cmd);

    strncpy(buffer, cmd, sizeof(buffer)-1);

    const char *argv[MAX_CMD_ARGS];
    char *next = buffer;
    char *tmp;

    argv[0] = IPTABLES_PATH;
    int argc = 1;

    while ((tmp = strsep(&next, " "))) {
        argv[argc++] = tmp;
        if (argc == MAX_CMD_ARGS) {
            LOGE("iptables argument overflow");
            errno = E2BIG;
            return -1;
        }
    }
    argv[argc] = NULL;
    /* TODO(jpa): Once this stabilizes, remove logwrap() as it tends to wedge netd
     * Then just talk directly to the kernel via rtnetlink.
     */
    return logwrap(argc, argv, 0);
}


int BandwidthController::enableBandwidthControl(void) {
        /* Some of the initialCommands are allowed to fail */
        runCommands(cleanupCommands, sizeof(cleanupCommands)/sizeof(char*), true);
        runCommands(setupCommands, sizeof(setupCommands)/sizeof(char*), true);
        return runCommands(basicAccountingCommands,
                           sizeof(basicAccountingCommands)/sizeof(char*));

}

int BandwidthController::disableBandwidthControl(void) {
        /* The cleanupCommands are allowed to fail */
        runCommands(cleanupCommands, sizeof(cleanupCommands)/sizeof(char*), true);
        return 0;
}

int BandwidthController::runCommands(const char *commands[], int numCommands, bool allowFailure) {
        int res = 0;
        LOGD("runCommands(): %d commands", numCommands);
        for (int cmdNum = 0; cmdNum < numCommands; cmdNum++) {
                res = runIptablesCmd(commands[cmdNum]);
                if(res && !allowFailure) return res;
        }
        return allowFailure?res:0;
}


int BandwidthController::setInterfaceQuota(const char *iface,
                                           int64_t maxBytes) {
    char cmd[MAX_CMD_LEN];
    char ifn[MAX_IFACENAME_LEN];
    int res;

    memset(ifn, 0, sizeof(ifn));
    strncpy(ifn, iface, sizeof(ifn)-1);

    if (maxBytes == -1) {
        return removeQuota(ifn);
    }

    /* Insert ingress quota. */
    std::string ifaceName(ifn);
    std::list<std::string>::iterator it;
    int pos;
    for (pos=1, it = ifaceRules.begin(); it != ifaceRules.end(); it++, pos++) {
            if (*it == ifaceName)
                    break;
    }
    if (it != ifaceRules.end()) {
            snprintf(cmd, sizeof(cmd), "-R INPUT %d -i %s --goto costly", pos, ifn);
            res = runIptablesCmd(cmd);
            snprintf(cmd, sizeof(cmd), "-R OUTPUT %d -o %s --goto costly", pos, ifn);
            res |= runIptablesCmd(cmd);
            snprintf(cmd, sizeof(cmd), "-R costly %d -m quota ! --quota %lld"
                    " --jump REJECT --reject-with icmp-net-prohibited",
                    pos, maxBytes);
            res |= runIptablesCmd(cmd);
            if (res) {
                    LOGE("Failed set quota rule.");
                    goto fail;
            }
    } else {
            pos = 1;
            snprintf(cmd, sizeof(cmd), "-I INPUT -i %s --goto costly", ifn);
            res = runIptablesCmd(cmd);
            snprintf(cmd, sizeof(cmd), "-I OUTPUT -o %s --goto costly", ifn);
            res |= runIptablesCmd(cmd);
            snprintf(cmd, sizeof(cmd), "-I costly -m quota ! --quota %lld"
                    " --jump REJECT --reject-with icmp-net-prohibited",
                    maxBytes);
            res |= runIptablesCmd(cmd);
            if (res) {
                    LOGE("Failed set quota rule.");
                    goto fail;
            }
            ifaceRules.push_front(ifaceName);
    }
    return 0;
fail:
    /*
     * Failure tends to be that the rules have been messed up.
     * For now cleanup all the rules.
     * TODO(jpa): once we get rid of iptables in favor of rtnetlink, reparse
     * rules in the kernel to see which ones need cleaning up.
     */
    runCommands(basicAccountingCommands,
                sizeof(basicAccountingCommands)/sizeof(char*), true);
    removeQuota(ifn);
    return -1;
}

int BandwidthController::removeQuota(const char *iface) {
    char cmd[MAX_CMD_LEN];
    char ifn[MAX_IFACENAME_LEN];
    int res;

    memset(ifn, 0, sizeof(ifn));
    strncpy(ifn, iface, sizeof(ifn)-1);

    std::string ifaceName(ifn);
    std::list<std::string>::iterator it;

    int pos;
    for (pos=1, it = ifaceRules.begin(); it != ifaceRules.end(); it++, pos++) {
            if (*it == ifaceName)
                    break;
    }
    if(it == ifaceRules.end()) {
            LOGE("No such iface %s to delete.", ifn);
            return -1;
    }
    ifaceRules.erase(it);
    snprintf(cmd, sizeof(cmd), "--delete INPUT -i %s --goto costly", ifn);
    res = runIptablesCmd(cmd);
    snprintf(cmd, sizeof(cmd), "--delete OUTPUT -o %s --goto costly", ifn);
    res |= runIptablesCmd(cmd);
    // Don't use rule-matching for this one. Quota is the remaining one.
    snprintf(cmd, sizeof(cmd), "--delete costly %d", pos);
    res |= runIptablesCmd(cmd);
    return res;
}
