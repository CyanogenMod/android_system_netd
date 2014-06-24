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

#include <arpa/inet.h>
#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <logwrap/logwrap.h>
#include <map>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

// Avoids "non-constant-expression cannot be narrowed from type 'unsigned int' to 'unsigned short'"
// warnings when using RTA_LENGTH(x) inside static initializers (even when x is already uint16_t).
#define U16_RTA_LENGTH(x) static_cast<uint16_t>(RTA_LENGTH((x)))

namespace {

const uint32_t RULE_PRIORITY_PRIVILEGED_LEGACY     = 11000;
const uint32_t RULE_PRIORITY_PER_NETWORK_EXPLICIT  = 13000;
const uint32_t RULE_PRIORITY_PER_NETWORK_INTERFACE = 14000;
const uint32_t RULE_PRIORITY_LEGACY                = 16000;
const uint32_t RULE_PRIORITY_PER_NETWORK_NORMAL    = 17000;
const uint32_t RULE_PRIORITY_DEFAULT_NETWORK       = 19000;
const uint32_t RULE_PRIORITY_MAIN                  = 20000;
// TODO: Uncomment once we are sure everything works.
#if 0
const uint32_t RULE_PRIORITY_UNREACHABLE           = 21000;
#endif

// TODO: These should be turned into per-UID tables once the kernel supports UID-based routing.
const int ROUTE_TABLE_PRIVILEGED_LEGACY = RouteController::ROUTE_TABLE_OFFSET_FROM_INDEX - 901;
const int ROUTE_TABLE_LEGACY            = RouteController::ROUTE_TABLE_OFFSET_FROM_INDEX - 902;

std::map<std::string, uint32_t> interfaceToIndex;

uint32_t getRouteTableForInterface(const char* interface) {
    uint32_t index = if_nametoindex(interface);
    if (index) {
        interfaceToIndex[interface] = index;
    } else {
        // If the interface goes away if_nametoindex() will return 0 but we still need to know
        // the index so we can remove the rules and routes.
        std::map<std::string, uint32_t>::iterator it = interfaceToIndex.find(interface);
        if (it != interfaceToIndex.end())
            index = it->second;
    }
    return index ? index + RouteController::ROUTE_TABLE_OFFSET_FROM_INDEX : 0;
}

// Adds or removes a routing rule for IPv4 and IPv6.
//
// + If |table| is non-zero, the rule points at the specified routing table. Otherwise, the rule
//   returns ENETUNREACH.
// + If |mask| is non-zero, the rule matches the specified fwmark and mask. Otherwise, |fwmark| is
//   ignored.
// + If |interface| is non-NULL, the rule matches the specified outgoing interface.
bool runIpRuleCommand(const char* action, uint32_t priority, uint32_t table, uint32_t fwmark,
                      uint32_t mask, const char* interface) {
    char priorityString[UINT32_STRLEN];
    snprintf(priorityString, sizeof(priorityString), "%u", priority);

    char tableString[UINT32_STRLEN];
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
        if (table) {
            argv[argc++] = "table";
            argv[argc++] = tableString;
        } else {
            argv[argc++] = "unreachable";
        }
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

#if 0

// Adds or deletes an IPv4 or IPv6 route.
// Returns 0 on success or negative errno on failure.
int modifyIpRoute(uint16_t action, uint32_t table, const char* interface, const char* destination,
                  const char* nexthop) {
    // At least the destination must be non-null.
    if (!destination) {
        return -EFAULT;
    }

    // Parse the prefix.
    uint8_t rawAddress[sizeof(in6_addr)];
    uint8_t family, prefixLength;
    int rawLength = parsePrefix(destination, &family, rawAddress, sizeof(rawAddress),
                                &prefixLength);
    if (rawLength < 0) {
        return rawLength;
    }

    if (static_cast<size_t>(rawLength) > sizeof(rawAddress)) {
        return -ENOBUFS;  // Cannot happen; parsePrefix only supports IPv4 and IPv6.
    }

    // If an interface was specified, find the ifindex.
    uint32_t ifindex;
    if (interface) {
        ifindex = if_nametoindex(interface);
        if (!ifindex) {
            return -ENODEV;
        }
    }

    // If a nexthop was specified, parse it as the same family as the prefix.
    uint8_t rawNexthop[sizeof(in6_addr)];
    if (nexthop && !inet_pton(family, nexthop, rawNexthop)) {
        return -EINVAL;
    }

    // Assemble a netlink request and put it in an array of iovec structures.
    nlmsghdr nlmsg = {
        .nlmsg_type = action,
        .nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
    };
    rtmsg rtmsg = {
        .rtm_protocol = RTPROT_STATIC,
        .rtm_type = RTN_UNICAST,
        .rtm_family = family,
        .rtm_dst_len = prefixLength,
    };
    rtattr rta_table = { U16_RTA_LENGTH(sizeof(table)), RTA_TABLE };
    rtattr rta_oif = { U16_RTA_LENGTH(sizeof(ifindex)), RTA_OIF };
    rtattr rta_dst = { U16_RTA_LENGTH(rawLength), RTA_DST };
    rtattr rta_gateway = { U16_RTA_LENGTH(rawLength), RTA_GATEWAY };
    if (action == RTM_NEWROUTE) {
        nlmsg.nlmsg_flags |= (NLM_F_CREATE | NLM_F_EXCL);
    }

    iovec iov[] = {
        { &nlmsg,        sizeof(nlmsg) },
        { &rtmsg,        sizeof(rtmsg) },
        { &rta_table,    sizeof(rta_table) },
        { &table,        sizeof(table) },
        { &rta_dst,      sizeof(rta_dst) },
        { rawAddress,    static_cast<size_t>(rawLength) },
        { &rta_oif,      interface ? sizeof(rta_oif) : 0 },
        { &ifindex,      interface ? sizeof(interface) : 0 },
        { &rta_gateway,  nexthop ? sizeof(rta_gateway) : 0 },
        { rawNexthop,    nexthop ? static_cast<size_t>(rawLength) : 0 },
    };
    int iovlen = ARRAY_SIZE(iov);

    for (int i = 0; i < iovlen; ++i) {
        nlmsg.nlmsg_len += iov[i].iov_len;
    }

    int ret;
    struct {
        nlmsghdr msg;
        nlmsgerr err;
    } response;

    sockaddr_nl kernel = {AF_NETLINK, 0, 0, 0};
    int sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if (sock != -1 &&
            connect(sock, reinterpret_cast<sockaddr *>(&kernel), sizeof(kernel)) != -1 &&
            writev(sock, iov, iovlen) != -1 &&
            (ret = recv(sock, &response, sizeof(response), 0)) != -1) {
        if (ret == sizeof(response)) {
            ret = response.err.error;  // Netlink errors are negative errno.
        } else {
            ret = -EBADMSG;
        }
    } else {
        ret = -errno;
    }

    if (sock != -1) {
        close(sock);
    }

    return ret;
}

#else

int modifyIpRoute(int action, uint32_t table, const char* interface, const char* destination,
                  const char* nexthop) {
    char tableString[UINT32_STRLEN];
    snprintf(tableString, sizeof(tableString), "%u", table);

    int argc = 0;
    const char* argv[16];

    argv[argc++] = IP_PATH;
    argv[argc++] = "route";
    argv[argc++] = action == RTM_NEWROUTE ? ADD : DEL;
    argv[argc++] = "table";
    argv[argc++] = tableString;
    if (destination) {
        argv[argc++] = destination;
        argv[argc++] = "dev";
        argv[argc++] = interface;
        if (nexthop) {
            argv[argc++] = "via";
            argv[argc++] = nexthop;
        }
    }
    return android_fork_execvp(argc, const_cast<char**>(argv), NULL, false, false);
}

#endif

bool modifyPerNetworkRules(unsigned netId, const char* interface, Permission permission, bool add,
                           bool modifyIptables) {
    uint32_t table = getRouteTableForInterface(interface);
    if (!table) {
        return false;
    }

    const char* action = add ? ADD : DEL;

    Fwmark fwmark;
    fwmark.permission = permission;

    Fwmark mask;
    mask.permission = permission;

    // A rule to route traffic based on a chosen outgoing interface.
    //
    // Supports apps that use SO_BINDTODEVICE or IP_PKTINFO options and the kernel that already
    // knows the outgoing interface (typically for link-local communications).
    if (!runIpRuleCommand(action, RULE_PRIORITY_PER_NETWORK_INTERFACE, table, fwmark.intValue,
                          mask.intValue, interface)) {
        return false;
    }

    // A rule to route traffic based on the chosen network.
    //
    // This is for sockets that have not explicitly requested a particular network, but have been
    // bound to one when they called connect(). This ensures that sockets connected on a particular
    // network stay on that network even if the default network changes.
    fwmark.netId = netId;
    mask.netId = FWMARK_NET_ID_MASK;
    if (!runIpRuleCommand(action, RULE_PRIORITY_PER_NETWORK_NORMAL, table, fwmark.intValue,
                          mask.intValue, NULL)) {
        return false;
    }

    // A rule to route traffic based on an explicitly chosen network.
    //
    // Supports apps that use the multinetwork APIs to restrict their traffic to a network.
    //
    // We don't really need to check the permission bits of the fwmark here, as they would've been
    // checked at the time the netId was set into the fwmark, but we do so to be consistent.
    fwmark.explicitlySelected = true;
    mask.explicitlySelected = true;
    if (!runIpRuleCommand(action, RULE_PRIORITY_PER_NETWORK_EXPLICIT, table, fwmark.intValue,
                          mask.intValue, NULL)) {
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

    Fwmark fwmark;
    fwmark.netId = 0;
    fwmark.permission = permission;

    Fwmark mask;
    mask.netId = FWMARK_NET_ID_MASK;
    mask.permission = permission;

    return runIpRuleCommand(action, RULE_PRIORITY_DEFAULT_NETWORK, table, fwmark.intValue,
                            mask.intValue, NULL);
}

// Adds or removes an IPv4 or IPv6 route to the specified table and, if it's directly-connected
// route, to the main table as well.
// Returns 0 on success or negative errno on failure.
int modifyRoute(const char* interface, const char* destination, const char* nexthop,
                int action, RouteController::TableType tableType, unsigned /* uid */) {
    uint32_t table = 0;
    switch (tableType) {
        case RouteController::INTERFACE: {
            table = getRouteTableForInterface(interface);
            break;
        }
        case RouteController::LEGACY: {
            // TODO: Use the UID to assign a unique table per UID instead of this fixed table.
            table = ROUTE_TABLE_LEGACY;
            break;
        }
        case RouteController::PRIVILEGED_LEGACY: {
            // TODO: Use the UID to assign a unique table per UID instead of this fixed table.
            table = ROUTE_TABLE_PRIVILEGED_LEGACY;
            break;
        }
    }
    if (!table) {
        return -ESRCH;
    }

    int ret = modifyIpRoute(action, table, interface, destination, nexthop);
    if (ret != 0) {
        return ret;
    }

    // If there's no nexthop, this is a directly connected route. Add it to the main table also, to
    // let the kernel find it when validating nexthops when global routes are added.
    if (!nexthop) {
        ret = modifyIpRoute(action, RT_TABLE_MAIN, interface, destination, NULL);
        // A failure with action == ADD && errno == EEXIST means that the route already exists in
        // the main table, perhaps because the kernel added it automatically as part of adding the
        // IP address to the interface. Ignore this, but complain about everything else.
        if (ret != 0 && !(action == RTM_NEWROUTE && ret == -EEXIST)) {
            return ret;
        }
    }

    return 0;
}

bool flushRoutes(const char* interface) {
    uint32_t table = getRouteTableForInterface(interface);
    if (!table) {
        return false;
    }
    interfaceToIndex.erase(interface);

    char tableString[UINT32_STRLEN];
    snprintf(tableString, sizeof(tableString), "%u", table);

    const char* version[] = {"-4", "-6"};
    for (size_t i = 0; i < ARRAY_SIZE(version); ++i) {
        const char* argv[] = {
            IP_PATH,
            version[i],
            "route"
            "flush",
            "table",
            tableString,
        };
        int argc = ARRAY_SIZE(argv);

        if (!android_fork_execvp(argc, const_cast<char**>(argv), NULL, false, false)) {
            return false;
        }
    }

    return true;
}

}  // namespace

void RouteController::Init() {
    // Add a new rule to look up the 'main' table, with the same selectors as the "default network"
    // rule, but with a lower priority. Since the default network rule points to a table with a
    // default route, the rule we're adding will never be used for normal routing lookups. However,
    // the kernel may fall-through to it to find directly-connected routes when it validates that a
    // nexthop (in a route being added) is reachable.
    Fwmark fwmark;
    fwmark.netId = 0;

    Fwmark mask;
    mask.netId = FWMARK_NET_ID_MASK;

    runIpRuleCommand(ADD, RULE_PRIORITY_MAIN, RT_TABLE_MAIN, fwmark.intValue, mask.intValue, NULL);

    // Add rules to allow lookup of legacy routes.
    //
    // TODO: Remove these once the kernel supports UID-based routing. Instead, add them on demand
    // when routes are added.
    fwmark.netId = 0;
    mask.netId = 0;

    fwmark.explicitlySelected = false;
    mask.explicitlySelected = true;

    runIpRuleCommand(ADD, RULE_PRIORITY_LEGACY, ROUTE_TABLE_LEGACY, fwmark.intValue, mask.intValue,
                     NULL);

    fwmark.permission = PERMISSION_CONNECTIVITY_INTERNAL;
    mask.permission = PERMISSION_CONNECTIVITY_INTERNAL;

    runIpRuleCommand(ADD, RULE_PRIORITY_PRIVILEGED_LEGACY, ROUTE_TABLE_PRIVILEGED_LEGACY,
                     fwmark.intValue, mask.intValue, NULL);

// TODO: Uncomment once we are sure everything works.
#if 0
    // Add a rule to preempt the pre-defined "from all lookup main" rule. This ensures that packets
    // that are already marked with a specific NetId don't fall-through to the main table.
    runIpRuleCommand(ADD, RULE_PRIORITY_UNREACHABLE, 0, 0, 0, NULL);
#endif
}

bool RouteController::addInterfaceToNetwork(unsigned netId, const char* interface,
                                            Permission permission) {
    return modifyPerNetworkRules(netId, interface, permission, true, true);
}

bool RouteController::removeInterfaceFromNetwork(unsigned netId, const char* interface,
                                                 Permission permission) {
    return modifyPerNetworkRules(netId, interface, permission, false, true) &&
           flushRoutes(interface);
}

bool RouteController::modifyNetworkPermission(unsigned netId, const char* interface,
                                              Permission oldPermission, Permission newPermission) {
    // Add the new rules before deleting the old ones, to avoid race conditions.
    return modifyPerNetworkRules(netId, interface, newPermission, true, false) &&
           modifyPerNetworkRules(netId, interface, oldPermission, false, false);
}

bool RouteController::addToDefaultNetwork(const char* interface, Permission permission) {
    return modifyDefaultNetworkRules(interface, permission, ADD);
}

bool RouteController::removeFromDefaultNetwork(const char* interface, Permission permission) {
    return modifyDefaultNetworkRules(interface, permission, DEL);
}

int RouteController::addRoute(const char* interface, const char* destination,
                              const char* nexthop, TableType tableType, unsigned uid) {
    return modifyRoute(interface, destination, nexthop, RTM_NEWROUTE, tableType, uid);
}

int RouteController::removeRoute(const char* interface, const char* destination,
                                 const char* nexthop, TableType tableType, unsigned uid) {
    return modifyRoute(interface, destination, nexthop, RTM_DELROUTE, tableType, uid);
}
