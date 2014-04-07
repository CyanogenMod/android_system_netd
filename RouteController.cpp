/*
 * Copyright (C) 2014 The Android Open Source Project
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

#include "RouteController.h"

#include "Fwmark.h"
#include "NetdConstants.h"

#include <logwrap/logwrap.h>
#include <net/if.h>
#include <stdio.h>

namespace {

// TODO: Keep this in sync with the kernel.
const uint32_t ROUTE_TABLE_OFFSET_FROM_INDEX = 255;

const char* const RULE_PRIORITY_PER_NETWORK_EXPLICIT = "300";
const char* const RULE_PRIORITY_PER_NETWORK_OIF = "400";
const char* const RULE_PRIORITY_PER_NETWORK_NORMAL = "700";

const bool FWMARK_USE_NET_ID = true;
const bool FWMARK_USE_EXPLICIT = true;
const bool FWMARK_USE_PROTECT = true;

// TODO: Tell the kernel about the offset using sysctls during init.
uint32_t getRouteTableForInterface(const char* interface) {
    uint32_t index = static_cast<uint32_t>(if_nametoindex(interface));
    return index ? index + ROUTE_TABLE_OFFSET_FROM_INDEX : 0;
}

bool runIpRuleCommand(const char* action, const char* priority, const char* table,
                      const char* fwmark, const char* oif) {
    const char* version[] = {"-4", "-6"};
    for (size_t i = 0; i < ARRAY_SIZE(version); ++i) {
        int argc = 0;
        const char* argv[16];

        argv[argc++] = IP_PATH;
        argv[argc++] = version[i];
        argv[argc++] = "rule";
        argv[argc++] = action;
        argv[argc++] = "priority";
        argv[argc++] = priority;
        argv[argc++] = "table";
        argv[argc++] = table;
        if (fwmark) {
            argv[argc++] = "fwmark";
            argv[argc++] = fwmark;
        }
        if (oif) {
            argv[argc++] = "oif";
            argv[argc++] = oif;
        }
        if (android_fork_execvp(argc, const_cast<char**>(argv), NULL, false, false)) {
            return false;
        }
    }

    return true;
}

bool modifyNetwork(unsigned netId, const char* interface, Permission permission, bool add) {
    uint32_t table = getRouteTableForInterface(interface);
    if (!table) {
        return false;
    }

    char table_string[sizeof("0x12345678")];
    snprintf(table_string, sizeof(table_string), "0x%x", table);

    char mark_string[sizeof("0x12345678/0x12345678")];
    const char* action = add ? ADD : DEL;

    // A rule to route traffic based on an explicitly chosen network.
    //
    // Supports apps that use the multinetwork APIs to restrict their traffic to a network.
    //
    // We don't really need to check the permission bits of the fwmark here, as they would've been
    // checked at the time the netId was set into the fwmark, but we do so to be consistent.
    uint32_t fwmark = getFwmark(netId, FWMARK_USE_EXPLICIT, !FWMARK_USE_PROTECT, permission);
    uint32_t mask = getFwmarkMask(FWMARK_USE_NET_ID, FWMARK_USE_EXPLICIT, !FWMARK_USE_PROTECT,
                                  permission);
    snprintf(mark_string, sizeof(mark_string), "0x%x/0x%x", fwmark, mask);
    if (!runIpRuleCommand(action, RULE_PRIORITY_PER_NETWORK_EXPLICIT, table_string, mark_string,
                          NULL)) {
        return false;
    }

    // A rule to route traffic based on a chosen outgoing interface.
    //
    // Supports apps that use SO_BINDTODEVICE or IP_PKTINFO options and the kernel that already
    // knows the outgoing interface (typically for link-local communications).
    fwmark = getFwmark(0, !FWMARK_USE_EXPLICIT, !FWMARK_USE_PROTECT, permission);
    mask = getFwmark(!FWMARK_USE_NET_ID, !FWMARK_USE_EXPLICIT, !FWMARK_USE_PROTECT, permission);
    snprintf(mark_string, sizeof(mark_string), "0x%x/0x%x", fwmark, mask);
    if (!runIpRuleCommand(action, RULE_PRIORITY_PER_NETWORK_OIF, table_string, mark_string,
                          interface)) {
        return false;
    }

    // A rule to route traffic based on the chosen network.
    //
    // This is for sockets that have not explicitly requested a particular network, but have been
    // bound to one when they called connect(). This ensures that sockets connected on a particular
    // network stay on that network even if the default network changes.
    fwmark = getFwmark(netId, !FWMARK_USE_EXPLICIT, !FWMARK_USE_PROTECT, permission);
    mask = getFwmarkMask(FWMARK_USE_NET_ID, !FWMARK_USE_EXPLICIT, !FWMARK_USE_PROTECT, permission);
    snprintf(mark_string, sizeof(mark_string), "0x%x/0x%x", fwmark, mask);
    if (!runIpRuleCommand(action, RULE_PRIORITY_PER_NETWORK_NORMAL, table_string, mark_string,
                          NULL)) {
        return false;
    }

    // An iptables rule to mark incoming packets on a network with the netId of the network.
    //
    // This is so that the kernel can:
    // + Use the right fwmark for (and thus correctly route) replies (e.g.: TCP RST, ICMP errors,
    //   ping replies, etc).
    // + Mark sockets that accept connections from this interface so that the connection stays on
    //   the same interface.
    action = add ? "-A" : "-D";
    snprintf(mark_string, sizeof(mark_string), "0x%x", netId);
    if (execIptables(V4V6, "-t", "mangle", action, "INPUT", "-i", interface, "-j", "MARK",
                     "--set-mark", mark_string, NULL)) {
        return false;
    }

    return true;
}

}  // namespace

bool RouteController::createNetwork(unsigned netId, const char* interface, Permission permission) {
    return modifyNetwork(netId, interface, permission, true);
}

bool RouteController::destroyNetwork(unsigned netId, const char* interface, Permission permission) {
    return modifyNetwork(netId, interface, permission, false);
}
