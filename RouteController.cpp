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

namespace {

const uint32_t RULE_PRIORITY_PER_NETWORK_EXPLICIT  =  300;
const uint32_t RULE_PRIORITY_PER_NETWORK_INTERFACE =  400;
const uint32_t RULE_PRIORITY_PER_NETWORK_NORMAL    =  700;
const uint32_t RULE_PRIORITY_DEFAULT_NETWORK       =  900;

const bool FWMARK_USE_NET_ID   = true;
const bool FWMARK_USE_EXPLICIT = true;
const bool FWMARK_USE_PROTECT  = true;

uint32_t getRouteTableForInterface(const char* interface) {
    uint32_t index = if_nametoindex(interface);
    return index ? index + RouteController::ROUTE_TABLE_OFFSET_FROM_INDEX : 0;
}

bool runIpRuleCommand(const char* action, uint32_t priority, uint32_t table,
                      uint32_t fwmark, uint32_t mask, const char* interface) {

    char priorityString[UINT32_STRLEN];
    char tableString[UINT32_STRLEN];
    snprintf(priorityString, sizeof(priorityString), "%u", priority);
    snprintf(tableString, sizeof(tableString), "%u", table);

    char fwmarkString[sizeof("0x12345678/0x12345678")];
    snprintf(fwmarkString, sizeof(fwmarkString), "0x%x/0x%x", fwmark, mask);

    const char* version[] = {"-4", "-6"};
    for (size_t i = 0; i < ARRAY_SIZE(version); ++i) {
        int argc = 0;
        const char* argv[16];

        argv[argc++] = IP_PATH;
        argv[argc++] = version[i];
        argv[argc++] = "rule";
        argv[argc++] = action;
        argv[argc++] = "priority";
        argv[argc++] = priorityString;
        argv[argc++] = "table";
        argv[argc++] = tableString;
        if (mask) {
            argv[argc++] = "fwmark";
            argv[argc++] = fwmarkString;
        }
        if (interface) {
            argv[argc++] = "oif";
            argv[argc++] = interface;
        }
        if (android_fork_execvp(argc, const_cast<char**>(argv), NULL, false, false)) {
            return false;
        }
    }

    return true;
}

bool modifyPerNetworkRules(unsigned netId, const char* interface, Permission permission, bool add,
                           bool modifyIptables) {
    uint32_t table = getRouteTableForInterface(interface);
    if (!table) {
        return false;
    }

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
    if (!runIpRuleCommand(action, RULE_PRIORITY_PER_NETWORK_EXPLICIT, table, fwmark, mask, NULL)) {
        return false;
    }

    // A rule to route traffic based on a chosen outgoing interface.
    //
    // Supports apps that use SO_BINDTODEVICE or IP_PKTINFO options and the kernel that already
    // knows the outgoing interface (typically for link-local communications).
    fwmark = getFwmark(0, !FWMARK_USE_EXPLICIT, !FWMARK_USE_PROTECT, permission);
    mask = getFwmark(!FWMARK_USE_NET_ID, !FWMARK_USE_EXPLICIT, !FWMARK_USE_PROTECT, permission);
    if (!runIpRuleCommand(action, RULE_PRIORITY_PER_NETWORK_INTERFACE, table, fwmark, mask,
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
    if (!runIpRuleCommand(action, RULE_PRIORITY_PER_NETWORK_NORMAL, table, fwmark, mask, NULL)) {
        return false;
    }

    // An iptables rule to mark incoming packets on a network with the netId of the network.
    //
    // This is so that the kernel can:
    // + Use the right fwmark for (and thus correctly route) replies (e.g.: TCP RST, ICMP errors,
    //   ping replies).
    // + Mark sockets that accept connections from this interface so that the connection stays on
    //   the same interface.
    if (modifyIptables) {
        action = add ? "-A" : "-D";
        char markString[UINT32_HEX_STRLEN];
        snprintf(markString, sizeof(markString), "0x%x", netId);
        if (execIptables(V4V6, "-t", "mangle", action, "INPUT", "-i", interface, "-j", "MARK",
                         "--set-mark", markString, NULL)) {
            return false;
        }
    }

    return true;
}

bool modifyDefaultNetworkRules(const char* interface, Permission permission, const char* action) {
    uint32_t table = getRouteTableForInterface(interface);
    if (!table) {
        return false;
    }

    uint32_t fwmark = getFwmark(0, !FWMARK_USE_EXPLICIT, !FWMARK_USE_PROTECT, permission);
    uint32_t mask = getFwmarkMask(FWMARK_USE_NET_ID, !FWMARK_USE_EXPLICIT, !FWMARK_USE_PROTECT,
                                  permission);

    if (!runIpRuleCommand(action, RULE_PRIORITY_DEFAULT_NETWORK, table, fwmark, mask, NULL)) {
        return false;
    }

    return true;
}

}  // namespace

bool RouteController::createNetwork(unsigned netId, const char* interface, Permission permission) {
    return modifyPerNetworkRules(netId, interface, permission, true, true);
}

bool RouteController::destroyNetwork(unsigned netId, const char* interface, Permission permission) {
    return modifyPerNetworkRules(netId, interface, permission, false, true);
    // TODO: Flush the routing table.
}

bool RouteController::modifyNetworkPermission(unsigned netId, const char* interface,
                                              Permission oldPermission, Permission newPermission) {
    // Add the new rules before deleting the old ones, to avoid race conditions.
    return modifyPerNetworkRules(netId, interface, newPermission, true, false) &&
           modifyPerNetworkRules(netId, interface, oldPermission, false, false);
}

bool RouteController::addDefaultNetwork(const char* interface, Permission permission) {
    return modifyDefaultNetworkRules(interface, permission, ADD);
}

bool RouteController::removeDefaultNetwork(const char* interface, Permission permission) {
    return modifyDefaultNetworkRules(interface, permission, DEL);
}
