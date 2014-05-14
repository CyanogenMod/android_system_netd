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

#include <resolv_netid.h>

#define LOG_TAG "NetworkController"
#include <cutils/log.h>

#include "NetworkController.h"

#include "PermissionsController.h"
#include "RouteController.h"

namespace {

// Keep these in sync with ConnectivityService.java.
const unsigned int MIN_NET_ID = 10;
const unsigned int MAX_NET_ID = 65535;

}  // namespace

bool NetworkController::isNetIdValid(unsigned netId) {
    return MIN_NET_ID <= netId && netId <= MAX_NET_ID;
}

NetworkController::NetworkController(PermissionsController* permissionsController,
                                     RouteController* routeController)
        : mPermissionsController(permissionsController),
          mRouteController(routeController) {
}

void NetworkController::clearNetworkPreference() {
    android::RWLock::AutoWLock lock(mRWLock);
    mUidMap.clear();
}

unsigned NetworkController::getDefaultNetwork() const {
    android::RWLock::AutoRLock lock(mRWLock);
    return mDefaultNetId;
}

bool NetworkController::setDefaultNetwork(unsigned newNetId) {
    unsigned oldNetId;
    {
        android::RWLock::AutoWLock lock(mRWLock);
        oldNetId = mDefaultNetId;
        mDefaultNetId = newNetId;
    }

    if (oldNetId == newNetId) {
        return true;
    }

    bool status = true;

    // Add default network rules for the new netId.
    if (isNetIdValid(newNetId)) {
        Permission permission = mPermissionsController->getPermissionForNetwork(newNetId);
        InterfaceRange range = interfacesForNetId(newNetId, &status);
        for (InterfaceIterator iter = range.first; iter != range.second; ++iter) {
            if (!mRouteController->addDefaultNetwork(iter->second.c_str(), permission)) {
                status = false;
            }
        }
    }

    // Remove the old default network rules.
    if (isNetIdValid(oldNetId)) {
        Permission permission = mPermissionsController->getPermissionForNetwork(oldNetId);
        InterfaceRange range = interfacesForNetId(oldNetId, &status);
        for (InterfaceIterator iter = range.first; iter != range.second; ++iter) {
            if (!mRouteController->removeDefaultNetwork(iter->second.c_str(), permission)) {
                status = false;
            }
        }
    }

    return status;
}

bool NetworkController::setNetworkForUidRange(int uid_start, int uid_end, unsigned netId,
        bool forward_dns) {
    android::RWLock::AutoWLock lock(mRWLock);
    if (uid_start > uid_end || !isNetIdValid(netId))
        return false;

    for (std::list<UidEntry>::iterator it = mUidMap.begin(); it != mUidMap.end(); ++it) {
        if (it->uid_start != uid_start || it->uid_end != uid_end || it->netId != netId)
            continue;
        it->forward_dns = forward_dns;
        return true;
    }

    mUidMap.push_front(UidEntry(uid_start, uid_end, netId, forward_dns));
    return true;
}

bool NetworkController::clearNetworkForUidRange(int uid_start, int uid_end, unsigned netId) {
    android::RWLock::AutoWLock lock(mRWLock);
    if (uid_start > uid_end || !isNetIdValid(netId))
        return false;

    for (std::list<UidEntry>::iterator it = mUidMap.begin(); it != mUidMap.end(); ++it) {
        if (it->uid_start != uid_start || it->uid_end != uid_end || it->netId != netId)
            continue;
        mUidMap.erase(it);
        return true;
    }
    return false;
}

unsigned NetworkController::getNetwork(int uid, unsigned requested_netId, bool for_dns) const {
    android::RWLock::AutoRLock lock(mRWLock);
    for (std::list<UidEntry>::const_iterator it = mUidMap.begin(); it != mUidMap.end(); ++it) {
        if (uid < it->uid_start || it->uid_end < uid)
            continue;
        if (for_dns && !it->forward_dns)
            break;
        return it->netId;
    }
    if (isNetIdValid(requested_netId))
        return requested_netId;
    return mDefaultNetId;
}

unsigned NetworkController::getNetworkId(const char* interface) {
    std::map<std::string, unsigned>::const_iterator it = mIfaceNetidMap.find(interface);
    if (it != mIfaceNetidMap.end())
        return it->second;
    return NETID_UNSET;
}

bool NetworkController::createNetwork(unsigned netId, Permission permission) {
    if (!isNetIdValid(netId)) {
        ALOGE("invalid netId %u", netId);
        return false;
    }

    mPermissionsController->setPermissionForNetwork(permission, netId);
    return true;
}

bool NetworkController::addInterfaceToNetwork(unsigned netId, const char* interface) {
    if (!isNetIdValid(netId) || !interface) {
        ALOGE("invalid netId %u or interface null", netId);
        return false;
    }

    unsigned existingNetId = netIdForInterface(interface);
    if (existingNetId != NETID_UNSET) {
        ALOGE("interface %s already assigned to netId %u", interface, existingNetId);
        return false;
    }

    Permission permission = mPermissionsController->getPermissionForNetwork(netId);
    if (!mRouteController->addInterfaceToNetwork(netId, interface, permission)) {
        ALOGE("failed to add rules for interface %s to netId %u", interface, netId);
        return false;
    }

    mNetIdToInterfaces.insert(std::pair<unsigned, std::string>(netId, interface));
    mIfaceNetidMap[interface] = netId;

    if (netId == getDefaultNetwork() &&
            !mRouteController->addDefaultNetwork(interface, permission)) {
        ALOGE("failed to add interface %s to default network %u", interface, netId);
        return false;
    }

    return true;
}

bool NetworkController::removeInterfaceFromNetwork(unsigned netId, const char* interface) {
    if (!isNetIdValid(netId) || !interface) {
        ALOGE("invalid netId %u or interface null", netId);
        return false;
    }

    bool status = true;
    bool found = false;
    InterfaceRange range = interfacesForNetId(netId, &status);
    for (InterfaceIterator iter = range.first; iter != range.second; ++iter) {
        if (iter->second == interface) {
            mNetIdToInterfaces.erase(iter);
            found = true;
            break;
        }
    }
    if (!found) {
        ALOGE("interface %s not a member of netId %u", interface, netId);
        status = false;
    }

    Permission permission = mPermissionsController->getPermissionForNetwork(netId);
    if (!mRouteController->removeInterfaceFromNetwork(netId, interface, permission)) {
        ALOGE("failed to remove rules for interface %s from netId %u", interface, netId);
        status = false;
    }

    if (netId == getDefaultNetwork() &&
            !mRouteController->removeDefaultNetwork(interface, permission)) {
        ALOGE("failed to remove interface %s from default network %u", interface, netId);
        status = false;
    }

    mIfaceNetidMap.erase(interface);

    return status;
}

bool NetworkController::destroyNetwork(unsigned netId) {
    if (!isNetIdValid(netId)) {
        ALOGE("invalid netId %u", netId);
        return false;
    }

    // TODO: ioctl(SIOCKILLADDR, ...) to kill all sockets on the old network.

    bool status = true;

    InterfaceRange range = interfacesForNetId(netId, &status);
    for (InterfaceIterator iter = range.first; iter != range.second; ) {
        InterfaceIterator toErase = iter;
        ++iter;
        if (!removeInterfaceFromNetwork(netId, toErase->second.c_str())) {
            status = false;
        }
    }

    if (netId == getDefaultNetwork()) {
        // Could the default network have changed from below us, after we evaluated the 'if', making
        // it wrong to call setDefaultNetwork() now? No, because the default can only change due to
        // a command from CommandListener; but commands are serialized, I.e., we are processing the
        // destroyNetwork() command here, so a setDefaultNetwork() command can't happen in parallel.
        setDefaultNetwork(NETID_UNSET);
    }

    mPermissionsController->setPermissionForNetwork(PERMISSION_NONE, netId);

    _resolv_delete_cache_for_net(netId);
    return status;
}

bool NetworkController::setPermissionForUser(Permission permission,
                                             const std::vector<unsigned>& uid) {
    for (size_t i = 0; i < uid.size(); ++i) {
        mPermissionsController->setPermissionForUser(permission, uid[i]);
    }
    return true;
}

bool NetworkController::setPermissionForNetwork(Permission newPermission,
                                                const std::vector<unsigned>& netId) {
    bool status = true;

    for (size_t i = 0; i < netId.size(); ++i) {
        if (!isNetIdValid(netId[i])) {
            ALOGE("invalid netId %u", netId[i]);
            status = false;
            continue;
        }

        InterfaceRange range = interfacesForNetId(netId[i], &status);

        Permission oldPermission = mPermissionsController->getPermissionForNetwork(netId[i]);
        if (oldPermission == newPermission) {
            continue;
        }

        // TODO: ioctl(SIOCKILLADDR, ...) to kill sockets on the network that don't have
        // newPermission.

        for (InterfaceIterator iter = range.first; iter != range.second; ++iter) {
            if (!mRouteController->modifyNetworkPermission(netId[i], iter->second.c_str(),
                                                           oldPermission, newPermission)) {
                status = false;
            }
        }

        mPermissionsController->setPermissionForNetwork(newPermission, netId[i]);
    }

    return status;
}

bool NetworkController::addRoute(unsigned netId, const char* interface, const char* destination,
                                 const char* nexthop) {
    return modifyRoute(netId, interface, destination, nexthop, true);
}

bool NetworkController::removeRoute(unsigned netId, const char* interface, const char* destination,
                                    const char* nexthop) {
    return modifyRoute(netId, interface, destination, nexthop, false);
}

unsigned NetworkController::netIdForInterface(const char* interface) {
    for (InterfaceIterator iter = mNetIdToInterfaces.begin(); iter != mNetIdToInterfaces.end();
         ++iter) {
        if (iter->second == interface) {
            return iter->first;
        }
    }
    return NETID_UNSET;
}

NetworkController::InterfaceRange NetworkController::interfacesForNetId(unsigned netId,
                                                                        bool* status) {
    InterfaceRange range = mNetIdToInterfaces.equal_range(netId);
    if (range.first == range.second) {
        ALOGE("unknown netId %u", netId);
        *status = false;
    }
    return range;
}

bool NetworkController::modifyRoute(unsigned netId, const char* interface, const char* destination,
                                    const char* nexthop, bool add) {
    if (!isNetIdValid(netId)) {
        ALOGE("invalid netId %u", netId);
        return false;
    }

    if (netIdForInterface(interface) != netId) {
        ALOGE("netId %u has no such interface %s", netId, interface);
        return false;
    }

    return add ? mRouteController->addRoute(interface, destination, nexthop) :
                 mRouteController->removeRoute(interface, destination, nexthop);
}

NetworkController::UidEntry::UidEntry(
    int start, int end, unsigned netId, bool forward_dns)
      : uid_start(start),
        uid_end(end),
        netId(netId),
        forward_dns(forward_dns) {
}
