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

#ifndef SYSTEM_NETD_ROUTE_CONTROLLER_H
#define SYSTEM_NETD_ROUTE_CONTROLLER_H

#include "Permission.h"

class RouteController {
public:
    static const int ROUTE_TABLE_OFFSET_FROM_INDEX = 1000;

    static bool createNetwork(unsigned netId, const char* interface, Permission permission);
    static bool destroyNetwork(unsigned netId, const char* interface, Permission permission);
    static bool modifyNetworkPermission(unsigned netId, const char* interface,
                                        Permission oldPermission, Permission newPermission);

    static bool addDefaultNetwork(const char* interface, Permission permission);
    static bool removeDefaultNetwork(const char* interface, Permission permission);
};

#endif  // SYSTEM_NETD_ROUTE_CONTROLLER_H
