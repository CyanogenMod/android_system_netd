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

#ifndef NETD_SERVER_ROUTE_CONTROLLER_H
#define NETD_SERVER_ROUTE_CONTROLLER_H

#include "NetdConstants.h"
#include "Permission.h"

#include <sys/types.h>

class UidRanges;

class RouteController {
public:
    // How the routing table number is determined for route modification requests.
    enum TableType {
        INTERFACE,       // Compute the table number based on the interface index.
        LEGACY_NETWORK,  // Use a fixed table that's used to override the default network.
        LEGACY_SYSTEM,   // A fixed table, only modifiable by system apps; overrides VPNs too.
    };

    static const int ROUTE_TABLE_OFFSET_FROM_INDEX = 1000;

    static int Init() WARN_UNUSED_RESULT;

    static int addInterfaceToPhysicalNetwork(unsigned netId, const char* interface,
                                             Permission permission) WARN_UNUSED_RESULT;
    static int removeInterfaceFromPhysicalNetwork(unsigned netId, const char* interface,
                                                  Permission permission) WARN_UNUSED_RESULT;

    static int addInterfaceToVirtualNetwork(unsigned netId, const char* interface,
                                            const UidRanges& uidRanges) WARN_UNUSED_RESULT;
    static int removeInterfaceFromVirtualNetwork(unsigned netId, const char* interface,
                                                 const UidRanges& uidRanges) WARN_UNUSED_RESULT;

    static int modifyPhysicalNetworkPermission(unsigned netId, const char* interface,
                                               Permission oldPermission,
                                               Permission newPermission) WARN_UNUSED_RESULT;

    static int addUsersToVirtualNetwork(unsigned netId, const char* interface,
                                        const UidRanges& uidRanges) WARN_UNUSED_RESULT;
    static int removeUsersFromVirtualNetwork(unsigned netId, const char* interface,
                                             const UidRanges& uidRanges) WARN_UNUSED_RESULT;

    static int addInterfaceToDefaultNetwork(const char* interface,
                                            Permission permission) WARN_UNUSED_RESULT;
    static int removeInterfaceFromDefaultNetwork(const char* interface,
                                                 Permission permission) WARN_UNUSED_RESULT;

    static int addRoute(const char* interface, const char* destination, const char* nexthop,
                        TableType tableType) WARN_UNUSED_RESULT;
    static int removeRoute(const char* interface, const char* destination, const char* nexthop,
                           TableType tableType) WARN_UNUSED_RESULT;
};

#endif  // NETD_SERVER_ROUTE_CONTROLLER_H
