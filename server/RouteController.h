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

class RouteController {
public:
    // How the routing table number is determined for route modification requests.
    enum TableType {
        INTERFACE,  // Compute the table number based on the interface index.
        LEGACY,  // Based on the UID; such tables can override the default network routes.
        PRIVILEGED_LEGACY,  // Based on the UID; such tables can bypass VPNs.
    };

    static const int ROUTE_TABLE_OFFSET_FROM_INDEX = 1000;

    static int Init() WARN_UNUSED_RESULT;

    static int addInterfaceToNetwork(unsigned netId, const char* interface,
                                     Permission permission) WARN_UNUSED_RESULT;
    static int removeInterfaceFromNetwork(unsigned netId, const char* interface,
                                          Permission permission) WARN_UNUSED_RESULT;

    static int modifyNetworkPermission(unsigned netId, const char* interface,
                                       Permission oldPermission,
                                       Permission newPermission) WARN_UNUSED_RESULT;

    static int addToDefaultNetwork(const char* interface, Permission permission) WARN_UNUSED_RESULT;
    static int removeFromDefaultNetwork(const char* interface,
                                        Permission permission) WARN_UNUSED_RESULT;

    static int addRoute(const char* interface, const char* destination, const char* nexthop,
                        TableType tableType, uid_t uid) WARN_UNUSED_RESULT;
    static int removeRoute(const char* interface, const char* destination, const char* nexthop,
                           TableType tableType, uid_t uid) WARN_UNUSED_RESULT;
};

#endif  // NETD_SERVER_ROUTE_CONTROLLER_H
