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

#include "LocalNetwork.h"
#include "PhysicalNetwork.h"
#include "RouteController.h"
#include "VirtualNetwork.h"

#include "cutils/misc.h"
#define LOG_TAG "Netd"
#include "log/log.h"
#include "resolv_netid.h"

namespace {

// Keep these in sync with ConnectivityService.java.
const unsigned MIN_NET_ID = 10;
const unsigned MAX_NET_ID = 65535;

}  // namespace

NetworkController::NetworkController() : mDefaultNetId(NETID_UNSET) {
    mNetworks[LOCAL_NET_ID] = new LocalNetwork(LOCAL_NET_ID);
}

unsigned NetworkController::getDefaultNetwork() const {
    android::RWLock::AutoRLock lock(mRWLock);
    return mDefaultNetId;
}

int NetworkController::setDefaultNetwork(unsigned netId) {
    android::RWLock::AutoWLock lock(mRWLock);

    if (netId == mDefaultNetId) {
        return 0;
    }

    if (netId != NETID_UNSET) {
        Network* network = getNetworkLocked(netId);
        if (!network || network->getType() != Network::PHYSICAL) {
            ALOGE("invalid netId %u", netId);
            return -EINVAL;
        }
        if (int ret = static_cast<PhysicalNetwork*>(network)->addAsDefault()) {
            return ret;
        }
    }

    if (mDefaultNetId != NETID_UNSET) {
        Network* network = getNetworkLocked(mDefaultNetId);
        if (!network || network->getType() != Network::PHYSICAL) {
            ALOGE("cannot find previously set default network with netId %u", mDefaultNetId);
            return -ESRCH;
        }
        if (int ret = static_cast<PhysicalNetwork*>(network)->removeAsDefault()) {
            return ret;
        }
    }

    mDefaultNetId = netId;
    return 0;
}

unsigned NetworkController::getNetworkForUser(uid_t uid, unsigned requestedNetId,
                                              bool forDns) const {
    android::RWLock::AutoRLock lock(mRWLock);
    VirtualNetwork* virtualNetwork = getVirtualNetworkForUserLocked(uid);
    if (virtualNetwork && (!forDns || virtualNetwork->getHasDns())) {
        return virtualNetwork->getNetId();
    }
    return getNetworkLocked(requestedNetId) ? requestedNetId : mDefaultNetId;
}

unsigned NetworkController::getNetworkForInterface(const char* interface) const {
    android::RWLock::AutoRLock lock(mRWLock);
    for (const auto& entry : mNetworks) {
        if (entry.second->hasInterface(interface)) {
            return entry.first;
        }
    }
    return NETID_UNSET;
}

bool NetworkController::isVirtualNetwork(unsigned netId) const {
    android::RWLock::AutoRLock lock(mRWLock);
    Network* network = getNetworkLocked(netId);
    return network && network->getType() == Network::VIRTUAL;
}

int NetworkController::createPhysicalNetwork(unsigned netId, Permission permission) {
    if (netId < MIN_NET_ID || netId > MAX_NET_ID) {
        ALOGE("invalid netId %u", netId);
        return -EINVAL;
    }

    if (isValidNetwork(netId)) {
        ALOGE("duplicate netId %u", netId);
        return -EEXIST;
    }

    PhysicalNetwork* physicalNetwork = new PhysicalNetwork(netId);
    if (int ret = physicalNetwork->setPermission(permission)) {
        ALOGE("inconceivable! setPermission cannot fail on an empty network");
        delete physicalNetwork;
        return ret;
    }

    android::RWLock::AutoWLock lock(mRWLock);
    mNetworks[netId] = physicalNetwork;
    return 0;
}

int NetworkController::createVirtualNetwork(unsigned netId, bool hasDns) {
    if (netId < MIN_NET_ID || netId > MAX_NET_ID) {
        ALOGE("invalid netId %u", netId);
        return -EINVAL;
    }

    if (isValidNetwork(netId)) {
        ALOGE("duplicate netId %u", netId);
        return -EEXIST;
    }

    android::RWLock::AutoWLock lock(mRWLock);
    mNetworks[netId] = new VirtualNetwork(netId, hasDns);
    return 0;
}

int NetworkController::destroyNetwork(unsigned netId) {
    if (netId == LOCAL_NET_ID || !isValidNetwork(netId)) {
        ALOGE("invalid netId %u", netId);
        return -EINVAL;
    }

    // TODO: ioctl(SIOCKILLADDR, ...) to kill all sockets on the old network.

    android::RWLock::AutoWLock lock(mRWLock);
    Network* network = getNetworkLocked(netId);
    if (int ret = network->clearInterfaces()) {
        return ret;
    }
    if (mDefaultNetId == netId) {
        if (int ret = static_cast<PhysicalNetwork*>(network)->removeAsDefault()) {
            ALOGE("inconceivable! removeAsDefault cannot fail on an empty network");
            return ret;
        }
        mDefaultNetId = NETID_UNSET;
    }
    mNetworks.erase(netId);
    delete network;
    _resolv_delete_cache_for_net(netId);
    return 0;
}

int NetworkController::addInterfaceToNetwork(unsigned netId, const char* interface) {
    if (!isValidNetwork(netId)) {
        ALOGE("invalid netId %u", netId);
        return -EINVAL;
    }

    unsigned existingNetId = getNetworkForInterface(interface);
    if (existingNetId != NETID_UNSET && existingNetId != netId) {
        ALOGE("interface %s already assigned to netId %u", interface, existingNetId);
        return -EBUSY;
    }

    android::RWLock::AutoWLock lock(mRWLock);
    return getNetworkLocked(netId)->addInterface(interface);
}

int NetworkController::removeInterfaceFromNetwork(unsigned netId, const char* interface) {
    if (!isValidNetwork(netId)) {
        ALOGE("invalid netId %u", netId);
        return -EINVAL;
    }

    android::RWLock::AutoWLock lock(mRWLock);
    return getNetworkLocked(netId)->removeInterface(interface);
}

Permission NetworkController::getPermissionForUser(uid_t uid) const {
    android::RWLock::AutoRLock lock(mRWLock);
    return getPermissionForUserLocked(uid);
}

void NetworkController::setPermissionForUsers(Permission permission,
                                              const std::vector<uid_t>& uids) {
    android::RWLock::AutoWLock lock(mRWLock);
    for (uid_t uid : uids) {
        mUsers[uid] = permission;
    }
}

bool NetworkController::canUserSelectNetwork(uid_t uid, unsigned netId) const {
    android::RWLock::AutoRLock lock(mRWLock);
    Network* network = getNetworkLocked(netId);
    if (!network || uid == INVALID_UID) {
        return false;
    }
    Permission userPermission = getPermissionForUserLocked(uid);
    if ((userPermission & PERMISSION_SYSTEM) == PERMISSION_SYSTEM) {
        return true;
    }
    if (network->getType() == Network::VIRTUAL) {
        return static_cast<VirtualNetwork*>(network)->appliesToUser(uid);
    }
    VirtualNetwork* virtualNetwork = getVirtualNetworkForUserLocked(uid);
    if (virtualNetwork && mProtectableUsers.find(uid) == mProtectableUsers.end()) {
        return false;
    }
    Permission networkPermission = static_cast<PhysicalNetwork*>(network)->getPermission();
    return (userPermission & networkPermission) == networkPermission;
}

int NetworkController::setPermissionForNetworks(Permission permission,
                                                const std::vector<unsigned>& netIds) {
    android::RWLock::AutoWLock lock(mRWLock);
    for (unsigned netId : netIds) {
        Network* network = getNetworkLocked(netId);
        if (!network || network->getType() != Network::PHYSICAL) {
            ALOGE("invalid netId %u", netId);
            return -EINVAL;
        }

        // TODO: ioctl(SIOCKILLADDR, ...) to kill socets on the network that don't have permission.

        if (int ret = static_cast<PhysicalNetwork*>(network)->setPermission(permission)) {
            return ret;
        }
    }
    return 0;
}

int NetworkController::addUsersToNetwork(unsigned netId, const UidRanges& uidRanges) {
    android::RWLock::AutoWLock lock(mRWLock);
    Network* network = getNetworkLocked(netId);
    if (!network || network->getType() != Network::VIRTUAL) {
        ALOGE("invalid netId %u", netId);
        return -EINVAL;
    }
    if (int ret = static_cast<VirtualNetwork*>(network)->addUsers(uidRanges)) {
        return ret;
    }
    return 0;
}

int NetworkController::removeUsersFromNetwork(unsigned netId, const UidRanges& uidRanges) {
    android::RWLock::AutoWLock lock(mRWLock);
    Network* network = getNetworkLocked(netId);
    if (!network || network->getType() != Network::VIRTUAL) {
        ALOGE("invalid netId %u", netId);
        return -EINVAL;
    }
    if (int ret = static_cast<VirtualNetwork*>(network)->removeUsers(uidRanges)) {
        return ret;
    }
    return 0;
}

int NetworkController::addRoute(unsigned netId, const char* interface, const char* destination,
                                const char* nexthop, bool legacy, uid_t uid) {
    return modifyRoute(netId, interface, destination, nexthop, true, legacy, uid);
}

int NetworkController::removeRoute(unsigned netId, const char* interface, const char* destination,
                                   const char* nexthop, bool legacy, uid_t uid) {
    return modifyRoute(netId, interface, destination, nexthop, false, legacy, uid);
}

bool NetworkController::canProtect(uid_t uid) const {
    android::RWLock::AutoRLock lock(mRWLock);
    return ((getPermissionForUserLocked(uid) & PERMISSION_SYSTEM) == PERMISSION_SYSTEM) ||
           mProtectableUsers.find(uid) != mProtectableUsers.end();
}

void NetworkController::allowProtect(const std::vector<uid_t>& uids) {
    android::RWLock::AutoWLock lock(mRWLock);
    mProtectableUsers.insert(uids.begin(), uids.end());
}

void NetworkController::denyProtect(const std::vector<uid_t>& uids) {
    android::RWLock::AutoWLock lock(mRWLock);
    for (uid_t uid : uids) {
        mProtectableUsers.erase(uid);
    }
}

bool NetworkController::isValidNetwork(unsigned netId) const {
    android::RWLock::AutoRLock lock(mRWLock);
    return getNetworkLocked(netId);
}

Network* NetworkController::getNetworkLocked(unsigned netId) const {
    auto iter = mNetworks.find(netId);
    return iter == mNetworks.end() ? NULL : iter->second;
}

VirtualNetwork* NetworkController::getVirtualNetworkForUserLocked(uid_t uid) const {
    for (const auto& entry : mNetworks) {
        if (entry.second->getType() == Network::VIRTUAL) {
            VirtualNetwork* virtualNetwork = static_cast<VirtualNetwork*>(entry.second);
            if (virtualNetwork->appliesToUser(uid)) {
                return virtualNetwork;
            }
        }
    }
    return NULL;
}

Permission NetworkController::getPermissionForUserLocked(uid_t uid) const {
    auto iter = mUsers.find(uid);
    if (iter != mUsers.end()) {
        return iter->second;
    }
    return uid < FIRST_APPLICATION_UID ? PERMISSION_SYSTEM : PERMISSION_NONE;
}

int NetworkController::modifyRoute(unsigned netId, const char* interface, const char* destination,
                                   const char* nexthop, bool add, bool legacy, uid_t uid) {
    unsigned existingNetId = getNetworkForInterface(interface);
    if (netId == NETID_UNSET || existingNetId != netId) {
        ALOGE("interface %s assigned to netId %u, not %u", interface, existingNetId, netId);
        return -ENOENT;
    }

    RouteController::TableType tableType;
    if (netId == LOCAL_NET_ID) {
        tableType = RouteController::LOCAL_NETWORK;
    } else if (legacy) {
        if ((getPermissionForUser(uid) & PERMISSION_SYSTEM) == PERMISSION_SYSTEM) {
            tableType = RouteController::LEGACY_SYSTEM;
        } else {
            tableType = RouteController::LEGACY_NETWORK;
        }
    } else {
        tableType = RouteController::INTERFACE;
    }

    return add ? RouteController::addRoute(interface, destination, nexthop, tableType) :
                 RouteController::removeRoute(interface, destination, nexthop, tableType);
}
