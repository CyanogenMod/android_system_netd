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

namespace {

Permission get(const std::map<unsigned, Permission>& map, unsigned id) {
    std::map<unsigned, Permission>::const_iterator iter = map.find(id);
    return iter != map.end() ? iter->second : PERMISSION_NONE;
}

void set(std::map<unsigned, Permission>* map, Permission permission, unsigned id) {
    if (permission == PERMISSION_NONE) {
        map->erase(id);
    } else {
        (*map)[id] = permission;
    }
}

}  // namespace

Permission PermissionsController::getPermissionForUser(unsigned uid) const {
    return get(mUsers, uid);
}

void PermissionsController::setPermissionForUser(Permission permission, unsigned uid) {
    set(&mUsers, permission, uid);
}

Permission PermissionsController::getPermissionForNetwork(unsigned netId) const {
    return get(mNetworks, netId);
}

void PermissionsController::setPermissionForNetwork(Permission permission, unsigned netId) {
    set(&mNetworks, permission, netId);
}

bool PermissionsController::isUserPermittedOnNetwork(unsigned uid, unsigned netId) const {
    Permission userPermission = getPermissionForUser(uid);
    Permission networkPermission = getPermissionForNetwork(netId);
    return (userPermission & networkPermission) == networkPermission;
}
