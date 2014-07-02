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

#include "PhysicalNetwork.h"

#include "RouteController.h"

#define LOG_TAG "Netd"
#include "log/log.h"

namespace {

WARN_UNUSED_RESULT int addToDefault(unsigned netId, const std::string& interface,
                                    Permission permission) {
    if (int ret = RouteController::addToDefaultNetwork(interface.c_str(), permission)) {
        ALOGE("failed to add interface %s to default netId %u", interface.c_str(), netId);
        return ret;
    }
    return 0;
}

WARN_UNUSED_RESULT int removeFromDefault(unsigned netId, const std::string& interface,
                                         Permission permission) {
    if (int ret = RouteController::removeFromDefaultNetwork(interface.c_str(), permission)) {
        ALOGE("failed to remove interface %s from default netId %u", interface.c_str(), netId);
        return ret;
    }
    return 0;
}

}  // namespace

PhysicalNetwork::PhysicalNetwork(unsigned netId) :
        Network(netId), mPermission(PERMISSION_NONE), mIsDefault(false) {
}

PhysicalNetwork::~PhysicalNetwork() {
}

Permission PhysicalNetwork::getPermission() const {
    return mPermission;
}

int PhysicalNetwork::setPermission(Permission permission) {
    if (permission == mPermission) {
        return 0;
    }
    for (const std::string& interface : mInterfaces) {
        if (int ret = RouteController::modifyNetworkPermission(mNetId, interface.c_str(),
                                                               mPermission, permission)) {
            ALOGE("failed to change permission on interface %s of netId %u from %x to %x",
                  interface.c_str(), mNetId, mPermission, permission);
            return ret;
        }
    }
    if (mIsDefault) {
        for (const std::string& interface : mInterfaces) {
            if (int ret = addToDefault(mNetId, interface, permission)) {
                return ret;
            }
            if (int ret = removeFromDefault(mNetId, interface, mPermission)) {
                return ret;
            }
        }
    }
    mPermission = permission;
    return 0;
}

int PhysicalNetwork::addAsDefault() {
    if (mIsDefault) {
        return 0;
    }
    for (const std::string& interface : mInterfaces) {
        if (int ret = addToDefault(mNetId, interface, mPermission)) {
            return ret;
        }
    }
    mIsDefault = true;
    return 0;
}

int PhysicalNetwork::removeAsDefault() {
    if (!mIsDefault) {
        return 0;
    }
    for (const std::string& interface : mInterfaces) {
        if (int ret = removeFromDefault(mNetId, interface, mPermission)) {
            return ret;
        }
    }
    mIsDefault = false;
    return 0;
}

Network::Type PhysicalNetwork::getType() const {
    return PHYSICAL;
}

int PhysicalNetwork::addInterface(const std::string& interface) {
    if (hasInterface(interface)) {
        return 0;
    }
    if (int ret = RouteController::addInterfaceToNetwork(mNetId, interface.c_str(), mPermission)) {
        ALOGE("failed to add interface %s to netId %u", interface.c_str(), mNetId);
        return ret;
    }
    if (mIsDefault) {
        if (int ret = addToDefault(mNetId, interface, mPermission)) {
            return ret;
        }
    }
    mInterfaces.insert(interface);
    return 0;
}

int PhysicalNetwork::removeInterface(const std::string& interface) {
    if (!hasInterface(interface)) {
        return 0;
    }
    if (int ret = RouteController::removeInterfaceFromNetwork(mNetId, interface.c_str(),
                                                              mPermission)) {
        ALOGE("failed to remove interface %s from netId %u", interface.c_str(), mNetId);
        return ret;
    }
    if (mIsDefault) {
        if (int ret = removeFromDefault(mNetId, interface, mPermission)) {
            return ret;
        }
    }
    mInterfaces.erase(interface);
    return 0;
}
