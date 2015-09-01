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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "FirewallController"
#define LOG_NDEBUG 0

#include <cutils/log.h>
#include <private/android_filesystem_config.h>

#include "NetdConstants.h"
#include "FirewallController.h"

const char* FirewallController::TABLE = "filter";

const char* FirewallController::LOCAL_INPUT = "fw_INPUT";
const char* FirewallController::LOCAL_OUTPUT = "fw_OUTPUT";
const char* FirewallController::LOCAL_FORWARD = "fw_FORWARD";

const char* FirewallController::LOCAL_DOZABLE = "fw_dozable";
const char* FirewallController::LOCAL_STANDBY = "fw_standby";

// ICMPv6 types that are required for any form of IPv6 connectivity to work. Note that because the
// fw_dozable chain is called from both INPUT and OUTPUT, this includes both packets that we need
// to be able to send (e.g., RS, NS), and packets that we need to receive (e.g., RA, NA).
const char* FirewallController::ICMPV6_TYPES[] = {
    "packet-too-big",
    "router-solicitation",
    "router-advertisement",
    "neighbour-solicitation",
    "neighbour-advertisement",
    "redirect",
};

FirewallController::FirewallController(void) {
    // If no rules are set, it's in BLACKLIST mode
    mFirewallType = BLACKLIST;
}

int FirewallController::setupIptablesHooks(void) {
    int res = 0;
    // child chains are created but not attached, they will be attached explicitly.
    FirewallType firewallType = getFirewallType(DOZABLE);
    res |= createChain(LOCAL_DOZABLE, LOCAL_INPUT, firewallType);

    firewallType = getFirewallType(STANDBY);
    res |= createChain(LOCAL_STANDBY, LOCAL_INPUT, firewallType);

    return res;
}

int FirewallController::enableFirewall(FirewallType ftype) {
    int res = 0;
    if (mFirewallType != ftype) {
        // flush any existing rules
        disableFirewall();

        if (ftype == WHITELIST) {
            // create default rule to drop all traffic
            res |= execIptables(V4V6, "-A", LOCAL_INPUT, "-j", "DROP", NULL);
            res |= execIptables(V4V6, "-A", LOCAL_OUTPUT, "-j", "REJECT", NULL);
            res |= execIptables(V4V6, "-A", LOCAL_FORWARD, "-j", "REJECT", NULL);
        }

        // Set this after calling disableFirewall(), since it defaults to WHITELIST there
        mFirewallType = ftype;
    }
    return res;
}

int FirewallController::disableFirewall(void) {
    int res = 0;

    mFirewallType = WHITELIST;

    // flush any existing rules
    res |= execIptables(V4V6, "-F", LOCAL_INPUT, NULL);
    res |= execIptables(V4V6, "-F", LOCAL_OUTPUT, NULL);
    res |= execIptables(V4V6, "-F", LOCAL_FORWARD, NULL);

    return res;
}

int FirewallController::enableChildChains(ChildChain chain, bool enable) {
    int res = 0;
    const char* name;
    switch(chain) {
        case DOZABLE:
            name = LOCAL_DOZABLE;
            break;
        case STANDBY:
            name = LOCAL_STANDBY;
            break;
        default:
            return res;
    }

    if (enable) {
        res |= attachChain(name, LOCAL_INPUT);
        res |= attachChain(name, LOCAL_OUTPUT);
    } else {
        res |= detachChain(name, LOCAL_INPUT);
        res |= detachChain(name, LOCAL_OUTPUT);
    }
    return res;
}

int FirewallController::isFirewallEnabled(void) {
    // TODO: verify that rules are still in place near top
    return -1;
}

int FirewallController::setInterfaceRule(const char* iface, FirewallRule rule) {
    if (mFirewallType == BLACKLIST) {
        // Unsupported in BLACKLIST mode
        return -1;
    }

    if (!isIfaceName(iface)) {
        errno = ENOENT;
        return -1;
    }

    const char* op;
    if (rule == ALLOW) {
        op = "-I";
    } else {
        op = "-D";
    }

    int res = 0;
    res |= execIptables(V4V6, op, LOCAL_INPUT, "-i", iface, "-j", "RETURN", NULL);
    res |= execIptables(V4V6, op, LOCAL_OUTPUT, "-o", iface, "-j", "RETURN", NULL);
    return res;
}

int FirewallController::setEgressSourceRule(const char* addr, FirewallRule rule) {
    if (mFirewallType == BLACKLIST) {
        // Unsupported in BLACKLIST mode
        return -1;
    }

    IptablesTarget target = V4;
    if (strchr(addr, ':')) {
        target = V6;
    }

    const char* op;
    if (rule == ALLOW) {
        op = "-I";
    } else {
        op = "-D";
    }

    int res = 0;
    res |= execIptables(target, op, LOCAL_INPUT, "-d", addr, "-j", "RETURN", NULL);
    res |= execIptables(target, op, LOCAL_OUTPUT, "-s", addr, "-j", "RETURN", NULL);
    return res;
}

int FirewallController::setEgressDestRule(const char* addr, int protocol, int port,
        FirewallRule rule) {
    if (mFirewallType == BLACKLIST) {
        // Unsupported in BLACKLIST mode
        return -1;
    }

    IptablesTarget target = V4;
    if (strchr(addr, ':')) {
        target = V6;
    }

    char protocolStr[16];
    sprintf(protocolStr, "%d", protocol);

    char portStr[16];
    sprintf(portStr, "%d", port);

    const char* op;
    if (rule == ALLOW) {
        op = "-I";
    } else {
        op = "-D";
    }

    int res = 0;
    res |= execIptables(target, op, LOCAL_INPUT, "-s", addr, "-p", protocolStr,
            "--sport", portStr, "-j", "RETURN", NULL);
    res |= execIptables(target, op, LOCAL_OUTPUT, "-d", addr, "-p", protocolStr,
            "--dport", portStr, "-j", "RETURN", NULL);
    return res;
}

FirewallType FirewallController::getFirewallType(ChildChain chain) {
    switch(chain) {
        case DOZABLE:
            return WHITELIST;
        case STANDBY:
            return BLACKLIST;
        case NONE:
            return mFirewallType;
        default:
            return BLACKLIST;
    }
}

int FirewallController::setUidRule(ChildChain chain, int uid, FirewallRule rule) {
    char uidStr[16];
    sprintf(uidStr, "%d", uid);

    const char* op;
    const char* target;
    FirewallType firewallType = getFirewallType(chain);
    if (firewallType == WHITELIST) {
        target = "RETURN";
        op = (rule == ALLOW)? "-I" : "-D";
    } else { // BLACKLIST mode
        target = "DROP";
        op = (rule == DENY)? "-I" : "-D";
    }

    int res = 0;
    switch(chain) {
        case DOZABLE:
            res |= execIptables(V4V6, op, LOCAL_DOZABLE, "-m", "owner", "--uid-owner",
                    uidStr, "-j", target, NULL);
            break;
        case STANDBY:
            res |= execIptables(V4V6, op, LOCAL_STANDBY, "-m", "owner", "--uid-owner",
                    uidStr, "-j", target, NULL);
            break;
        case NONE:
            res |= execIptables(V4V6, op, LOCAL_INPUT, "-m", "owner", "--uid-owner", uidStr,
                    "-j", target, NULL);
            res |= execIptables(V4V6, op, LOCAL_OUTPUT, "-m", "owner", "--uid-owner", uidStr,
                    "-j", target, NULL);
            break;
        default:
            ALOGW("Unknown child chain: %d", chain);
            break;
    }
    return res;
}

int FirewallController::attachChain(const char* childChain, const char* parentChain) {
    return execIptables(V4V6, "-t", TABLE, "-A", parentChain, "-j", childChain, NULL);
}

int FirewallController::detachChain(const char* childChain, const char* parentChain) {
    return execIptables(V4V6, "-t", TABLE, "-D", parentChain, "-j", childChain, NULL);
}

int FirewallController::createChain(const char* childChain,
        const char* parentChain, FirewallType type) {
    // Order is important, otherwise later steps may fail.
    execIptablesSilently(V4V6, "-t", TABLE, "-D", parentChain, "-j", childChain, NULL);
    execIptablesSilently(V4V6, "-t", TABLE, "-F", childChain, NULL);
    execIptablesSilently(V4V6, "-t", TABLE, "-X", childChain, NULL);
    int res = 0;
    res |= execIptables(V4V6, "-t", TABLE, "-N", childChain, NULL);
    if (type == WHITELIST) {
        // Allow ICMPv6 packets necessary to make IPv6 connectivity work. http://b/23158230 .
        for (size_t i = 0; i < ARRAY_SIZE(ICMPV6_TYPES); i++) {
            res |= execIptables(V6, "-A", childChain, "-p", "icmpv6", "--icmpv6-type",
                    ICMPV6_TYPES[i], "-j", "RETURN", NULL);
        }

        // create default white list for system uid range
        char uidStr[16];
        sprintf(uidStr, "0-%d", AID_APP - 1);
        res |= execIptables(V4V6, "-A", childChain, "-m", "owner", "--uid-owner",
                uidStr, "-j", "RETURN", NULL);

        // create default rule to drop all traffic
        res |= execIptables(V4V6, "-A", childChain, "-j", "DROP", NULL);
    }
    return res;
}
