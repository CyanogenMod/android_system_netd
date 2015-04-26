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

#include "NetdConstants.h"
#include "FirewallController.h"

const char* FirewallController::LOCAL_INPUT = "fw_INPUT";
const char* FirewallController::LOCAL_OUTPUT = "fw_OUTPUT";
const char* FirewallController::LOCAL_FORWARD = "fw_FORWARD";

FirewallController::FirewallController(void) {
    // If no rules are set, it's in BLACKLIST mode
    firewallType = BLACKLIST;
}

int FirewallController::setupIptablesHooks(void) {
    return 0;
}

int FirewallController::enableFirewall(FirewallType ftype) {
    int res = 0;

    // flush any existing rules
    disableFirewall();

    if (ftype == WHITELIST) {
        // create default rule to drop all traffic
        res |= execIptables(V4V6, "-A", LOCAL_INPUT, "-j", "DROP", NULL);
        res |= execIptables(V4V6, "-A", LOCAL_OUTPUT, "-j", "REJECT", NULL);
        res |= execIptables(V4V6, "-A", LOCAL_FORWARD, "-j", "REJECT", NULL);
    }

    // Set this after calling disableFirewall(), since it defaults to WHITELIST there
    firewallType = ftype;

    return res;
}

int FirewallController::disableFirewall(void) {
    int res = 0;

    firewallType = WHITELIST;

    // flush any existing rules
    res |= execIptables(V4V6, "-F", LOCAL_INPUT, NULL);
    res |= execIptables(V4V6, "-F", LOCAL_OUTPUT, NULL);
    res |= execIptables(V4V6, "-F", LOCAL_FORWARD, NULL);

    return res;
}

int FirewallController::isFirewallEnabled(void) {
    // TODO: verify that rules are still in place near top
    return -1;
}

int FirewallController::setInterfaceRule(const char* iface, FirewallRule rule) {
    if (firewallType == BLACKLIST) {
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
    if (firewallType == BLACKLIST) {
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
    if (firewallType == BLACKLIST) {
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

int FirewallController::setUidRule(int uid, FirewallRule rule) {
    char uidStr[16];
    sprintf(uidStr, "%d", uid);

    const char* op;
    const char* target;
    if (firewallType == WHITELIST) {
        target = "RETURN";
        op = (rule == ALLOW)? "-I" : "-D";
    } else { // BLACKLIST mode
        target = "DROP";
        op = (rule == DENY)? "-I" : "-D";
    }

    int res = 0;
    res |= execIptables(V4V6, op, LOCAL_INPUT, "-m", "owner", "--uid-owner", uidStr,
            "-j", target, NULL);
    res |= execIptables(V4V6, op, LOCAL_OUTPUT, "-m", "owner", "--uid-owner", uidStr,
            "-j", target, NULL);
    return res;
}
