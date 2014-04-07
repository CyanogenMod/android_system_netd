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

#include "PermissionsController.h"

Permission PermissionsController::getPermissionForNetwork(unsigned netId) const {
    std::map<unsigned, Permission>::const_iterator iter = mNetworks.find(netId);
    return iter != mNetworks.end() ? iter->second : PERMISSION_NONE;
}

void PermissionsController::setPermissionForNetwork(unsigned netId, Permission permission) {
    if (permission == PERMISSION_NONE) {
        clearPermissionForNetwork(netId);
        return;
    }
    mNetworks[netId] = permission;
}

void PermissionsController::clearPermissionForNetwork(unsigned netId) {
    mNetworks.erase(netId);
}
