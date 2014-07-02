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

#include "VirtualNetwork.h"

#include "RouteController.h"

#define LOG_TAG "Netd"
#include "log/log.h"

VirtualNetwork::VirtualNetwork(unsigned netId): Network(netId) {
}

VirtualNetwork::~VirtualNetwork() {
}

int VirtualNetwork::addInterface(const std::string& interface) {
    if (hasInterface(interface)) {
        return 0;
    }
    if (int ret = RouteController::addInterfaceToVpn(mNetId, interface.c_str(), mUidRanges)) {
        ALOGE("failed to add interface %s to VPN netId %u", interface.c_str(), mNetId);
        return ret;
    }
    mInterfaces.insert(interface);
    return 0;
}

int VirtualNetwork::removeInterface(const std::string& interface) {
    if (!hasInterface(interface)) {
        return 0;
    }
    if (int ret = RouteController::removeInterfaceFromVpn(mNetId, interface.c_str(), mUidRanges)) {
        ALOGE("failed to remove interface %s from VPN netId %u", interface.c_str(), mNetId);
        return ret;
    }
    mInterfaces.erase(interface);
    return 0;
}

Network::Type VirtualNetwork::getType() const {
    return VIRTUAL;
}

int VirtualNetwork::addUsers(const UidRanges& uidRanges) {
    for (const std::string& interface : mInterfaces) {
        if (int ret = RouteController::addUsersToVpn(mNetId, interface.c_str(), uidRanges)) {
            ALOGE("failed to add users on interface %s of netId %u", interface.c_str(), mNetId);
            return ret;
        }
    }
    mUidRanges.add(uidRanges);
    return 0;
}

int VirtualNetwork::removeUsers(const UidRanges& uidRanges) {
    for (const std::string& interface : mInterfaces) {
        if (int ret = RouteController::removeUsersFromVpn(mNetId, interface.c_str(), uidRanges)) {
            ALOGE("failed to remove users on interface %s of netId %u", interface.c_str(), mNetId);
            return ret;
        }
    }
    mUidRanges.remove(uidRanges);
    return 0;
}
