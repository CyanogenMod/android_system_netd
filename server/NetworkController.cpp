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

// THREAD-SAFETY
// -------------
// The methods in this file are called from multiple threads (from CommandListener, FwmarkServer
// and DnsProxyListener). So, all accesses to shared state are guarded by a lock.
//
// In some cases, a single non-const method acquires and releases the lock several times, like so:
//     if (isValidNetwork(...)) {  // isValidNetwork() acquires and releases the lock.
//        setDefaultNetwork(...);  // setDefaultNetwork() also acquires and releases the lock.
//
// It might seem that this allows races where the state changes between the two statements, but in
// fact there are no races because:
//     1. This pattern only occurs in non-const methods (i.e., those that mutate state).
//     2. Only CommandListener calls these non-const methods. The others call only const methods.
//     3. CommandListener only processes one command at a time. I.e., it's serialized.
// Thus, no other mutation can occur in between the two statements above.

#include "NetworkController.h"

#include "PermissionsController.h"
#include "RouteController.h"

#define LOG_TAG "NetworkController"

#include <sys/socket.h>
#include <linux/if.h>

#include "cutils/log.h"
#include "resolv_netid.h"

namespace {

// Keep these in sync with ConnectivityService.java.
const unsigned int MIN_NET_ID = 10;
const unsigned int MAX_NET_ID = 65535;

}  // namespace

NetworkController::NetworkController(PermissionsController* permissionsController,
                                     RouteController* routeController)
        : mDefaultNetId(NETID_UNSET),
          mPermissionsController(permissionsController),
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
    // newNetId must be either NETID_UNSET or a valid network. If it's NETID_UNSET, the caller is
    // asking for there to be no default network, which is a request we support.
    if (newNetId != NETID_UNSET && !isValidNetwork(newNetId)) {
        ALOGE("invalid netId %u", newNetId);
        errno = EINVAL;
        return false;
    }

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
    Permission permission;
    InterfaceRange range;

    // Add default network rules for the new netId.
    permission = mPermissionsController->getPermissionForNetwork(newNetId);
    range = mNetIdToInterfaces.equal_range(newNetId);
    for (InterfaceIteratorConst iter = range.first; iter != range.second; ++iter) {
        if (!mRouteController->addToDefaultNetwork(iter->second.c_str(), permission)) {
            ALOGE("failed to add interface %s to default netId %u", iter->second.c_str(), newNetId);
            status = false;
        }
    }

    // Remove the old default network rules.
    permission = mPermissionsController->getPermissionForNetwork(oldNetId);
    range = mNetIdToInterfaces.equal_range(oldNetId);
    for (InterfaceIteratorConst iter = range.first; iter != range.second; ++iter) {
        if (!mRouteController->removeFromDefaultNetwork(iter->second.c_str(), permission)) {
            ALOGE("failed to remove interface %s from default netId %u", iter->second.c_str(),
                  oldNetId);
            status = false;
        }
    }

    return status;
}

bool NetworkController::setNetworkForUidRange(int uid_start, int uid_end, unsigned netId,
                                              bool forward_dns) {
    if (uid_start > uid_end || !isValidNetwork(netId)) {
        errno = EINVAL;
        return false;
    }

    android::RWLock::AutoWLock lock(mRWLock);
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
    if (uid_start > uid_end || !isValidNetwork(netId)) {
        errno = EINVAL;
        return false;
    }

    android::RWLock::AutoWLock lock(mRWLock);
    for (std::list<UidEntry>::iterator it = mUidMap.begin(); it != mUidMap.end(); ++it) {
        if (it->uid_start != uid_start || it->uid_end != uid_end || it->netId != netId)
            continue;
        mUidMap.erase(it);
        return true;
    }

    errno = ENOENT;
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
    if (mValidNetworks.find(requested_netId) != mValidNetworks.end())
        return requested_netId;
    return mDefaultNetId;
}

unsigned NetworkController::getNetworkId(const char* interface) const {
    for (InterfaceIteratorConst iter = mNetIdToInterfaces.begin(); iter != mNetIdToInterfaces.end();
         ++iter) {
        if (iter->second == interface) {
            return iter->first;
        }
    }
    return NETID_UNSET;
}

bool NetworkController::createNetwork(unsigned netId, Permission permission) {
    if (netId < MIN_NET_ID || netId > MAX_NET_ID) {
        ALOGE("invalid netId %u", netId);
        errno = EINVAL;
        return false;
    }

    {
        android::RWLock::AutoWLock lock(mRWLock);
        if (!mValidNetworks.insert(netId).second) {
            ALOGE("duplicate netId %u", netId);
            errno = EEXIST;
            return false;
        }
    }

    mPermissionsController->setPermissionForNetwork(permission, netId);
    return true;
}

bool NetworkController::addInterfaceToNetwork(unsigned netId, const char* interface) {
    if (!isValidNetwork(netId) || !interface) {
        ALOGE("invalid netId %u or interface null", netId);
        errno = EINVAL;
        return false;
    }

    unsigned existingNetId = getNetworkId(interface);
    if (existingNetId != NETID_UNSET) {
        ALOGE("interface %s already assigned to netId %u", interface, existingNetId);
        errno = EBUSY;
        return false;
    }

    Permission permission = mPermissionsController->getPermissionForNetwork(netId);
    if (!mRouteController->addInterfaceToNetwork(netId, interface, permission)) {
        ALOGE("failed to add interface %s to netId %u", interface, netId);
        return false;
    }

    mNetIdToInterfaces.insert(std::pair<unsigned, std::string>(netId, interface));

    if (netId == getDefaultNetwork() &&
            !mRouteController->addToDefaultNetwork(interface, permission)) {
        ALOGE("failed to add interface %s to default netId %u", interface, netId);
        return false;
    }

    return true;
}

bool NetworkController::removeInterfaceFromNetwork(unsigned netId, const char* interface) {
    if (!isValidNetwork(netId) || !interface) {
        ALOGE("invalid netId %u or interface null", netId);
        errno = EINVAL;
        return false;
    }

    bool status = false;
    InterfaceRange range = mNetIdToInterfaces.equal_range(netId);
    for (InterfaceIterator iter = range.first; iter != range.second; ++iter) {
        if (iter->second == interface) {
            mNetIdToInterfaces.erase(iter);
            status = true;
            break;
        }
    }
    if (!status) {
        ALOGE("interface %s not assigned to netId %u", interface, netId);
        errno = ENOENT;
    }

    Permission permission = mPermissionsController->getPermissionForNetwork(netId);
    if (!mRouteController->removeInterfaceFromNetwork(netId, interface, permission)) {
        ALOGE("failed to remove interface %s from netId %u", interface, netId);
        status = false;
    }

    if (netId == getDefaultNetwork() &&
            !mRouteController->removeFromDefaultNetwork(interface, permission)) {
        ALOGE("failed to remove interface %s from default netId %u", interface, netId);
        status = false;
    }

    return status;
}

bool NetworkController::destroyNetwork(unsigned netId) {
    if (!isValidNetwork(netId)) {
        ALOGE("invalid netId %u", netId);
        errno = EINVAL;
        return false;
    }

    // TODO: ioctl(SIOCKILLADDR, ...) to kill all sockets on the old network.

    bool status = true;

    InterfaceRange range = mNetIdToInterfaces.equal_range(netId);
    for (InterfaceIteratorConst iter = range.first; iter != range.second; ) {
        char interface[IFNAMSIZ];
        strncpy(interface, iter->second.c_str(), sizeof(interface));
        interface[sizeof(interface) - 1] = 0;
        ++iter;
        if (!removeInterfaceFromNetwork(netId, interface)) {
            status = false;
        }
    }

    if (netId == getDefaultNetwork()) {
        setDefaultNetwork(NETID_UNSET);
    }

    {
        android::RWLock::AutoWLock lock(mRWLock);
        mValidNetworks.erase(netId);
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
        if (!isValidNetwork(netId[i])) {
            ALOGE("invalid netId %u", netId[i]);
            errno = EINVAL;
            status = false;
            continue;
        }

        Permission oldPermission = mPermissionsController->getPermissionForNetwork(netId[i]);
        if (oldPermission == newPermission) {
            continue;
        }

        // TODO: ioctl(SIOCKILLADDR, ...) to kill sockets on the network that don't have
        // newPermission.

        InterfaceRange range = mNetIdToInterfaces.equal_range(netId[i]);
        for (InterfaceIteratorConst iter = range.first; iter != range.second; ++iter) {
            if (!mRouteController->modifyNetworkPermission(netId[i], iter->second.c_str(),
                                                           oldPermission, newPermission)) {
                ALOGE("failed to change permission on interface %s of netId %u from %x to %x",
                      iter->second.c_str(), netId[i], oldPermission, newPermission);
                status = false;
            }
        }

        mPermissionsController->setPermissionForNetwork(newPermission, netId[i]);
    }

    return status;
}

bool NetworkController::addRoute(unsigned netId, const char* interface, const char* destination,
                                 const char* nexthop, bool legacy, unsigned uid) {
    return modifyRoute(netId, interface, destination, nexthop, true, legacy, uid);
}

bool NetworkController::removeRoute(unsigned netId, const char* interface, const char* destination,
                                    const char* nexthop, bool legacy, unsigned uid) {
    return modifyRoute(netId, interface, destination, nexthop, false, legacy, uid);
}

bool NetworkController::isValidNetwork(unsigned netId) const {
    if (netId == NETID_UNSET) {
        return false;
    }

    android::RWLock::AutoRLock lock(mRWLock);
    return mValidNetworks.find(netId) != mValidNetworks.end();
}

bool NetworkController::modifyRoute(unsigned netId, const char* interface, const char* destination,
                                    const char* nexthop, bool add, bool legacy, unsigned uid) {
    if (!isValidNetwork(netId)) {
        ALOGE("invalid netId %u", netId);
        errno = EINVAL;
        return false;
    }

    if (getNetworkId(interface) != netId) {
        ALOGE("netId %u has no such interface %s", netId, interface);
        errno = ENOENT;
        return false;
    }

    RouteController::TableType tableType;
    if (legacy) {
        if (mPermissionsController->getPermissionForUser(uid) & PERMISSION_CONNECTIVITY_INTERNAL) {
            tableType = RouteController::PRIVILEGED_LEGACY;
        } else {
            tableType = RouteController::LEGACY;
        }
    } else {
        tableType = RouteController::INTERFACE;
    }

    return add ? mRouteController->addRoute(interface, destination, nexthop, tableType, uid) :
                 mRouteController->removeRoute(interface, destination, nexthop, tableType, uid);
}

NetworkController::UidEntry::UidEntry(int start, int end, unsigned netId, bool forward_dns)
    : uid_start(start), uid_end(end), netId(netId), forward_dns(forward_dns) {
}
