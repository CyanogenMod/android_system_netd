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

#ifndef SYSTEM_NETD_PERMISSION_H
#define SYSTEM_NETD_PERMISSION_H

// This enum represents the permissions we care about for networking. When applied to an app, it's
// the permission the app (UID) has been granted. When applied to a network, it's the permission an
// app must hold to be allowed to use the network. PERMISSION_NONE means "no special permission is
// held by the app" or "no special permission is required to use the network".
//
// Permissions are flags that can be OR'ed together to represent combinations of permissions.
//
// NOTE: netd doesn't enforce any semantics for the permission values. E.g., while all apps with
// CONNECTIVITY_INTERNAL may also implicitly or explicitly have CHANGE_NETWORK_STATE, netd doesn't
// enforce it. It's the responsibility of the caller to set all permissions bits explicitly. I.e.,
// if you set the PERMISSION_CONNECTIVITY_INTERNAL bit, you should probably also set the
// PERMISSION_CHANGE_NETWORK_STATE bit.
enum Permission {
    PERMISSION_NONE                  = 0x0,
    PERMISSION_CHANGE_NETWORK_STATE  = 0x1,
    PERMISSION_CONNECTIVITY_INTERNAL = 0x2
};

Permission permissionFromString(const char* permission);

#endif  // SYSTEM_NETD_PERMISSION_H
