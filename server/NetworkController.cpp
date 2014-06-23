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

#include "PhysicalNetwork.h"
#include "RouteController.h"

#define LOG_TAG "Netd"
#include "log/log.h"
#include "resolv_netid.h"

namespace {

// Keep these in sync with ConnectivityService.java.
const unsigned MIN_NET_ID = 10;
const unsigned MAX_NET_ID = 65535;

}  // namespace

NetworkController::NetworkController() : mDefaultNetId(NETID_UNSET) {
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
        auto iter = mPhysicalNetworks.find(netId);
        if (iter == mPhysicalNetworks.end()) {
            ALOGE("invalid netId %u", netId);
            return -EINVAL;
        }
        if (int ret = iter->second->addAsDefault()) {
            return ret;
        }
    }

    if (mDefaultNetId != NETID_UNSET) {
        auto iter = mPhysicalNetworks.find(mDefaultNetId);
        if (iter == mPhysicalNetworks.end()) {
            ALOGE("cannot find previously set default network with netId %u", mDefaultNetId);
            return -ESRCH;
        }
        if (int ret = iter->second->removeAsDefault()) {
            return ret;
        }
    }

    mDefaultNetId = netId;
    return 0;
}

bool NetworkController::setNetworkForUidRange(uid_t uidStart, uid_t uidEnd, unsigned netId,
                                              bool forwardDns) {
    if (uidStart > uidEnd || !isValidNetwork(netId)) {
        errno = EINVAL;
        return false;
    }

    android::RWLock::AutoWLock lock(mRWLock);
    for (UidEntry& entry : mUidMap) {
        if (entry.uidStart == uidStart && entry.uidEnd == uidEnd && entry.netId == netId) {
            entry.forwardDns = forwardDns;
            return true;
        }
    }

    mUidMap.push_front(UidEntry(uidStart, uidEnd, netId, forwardDns));
    return true;
}

bool NetworkController::clearNetworkForUidRange(uid_t uidStart, uid_t uidEnd, unsigned netId) {
    if (uidStart > uidEnd || !isValidNetwork(netId)) {
        errno = EINVAL;
        return false;
    }

    android::RWLock::AutoWLock lock(mRWLock);
    for (auto iter = mUidMap.begin(); iter != mUidMap.end(); ++iter) {
        if (iter->uidStart == uidStart && iter->uidEnd == uidEnd && iter->netId == netId) {
            mUidMap.erase(iter);
            return true;
        }
    }

    errno = ENOENT;
    return false;
}

unsigned NetworkController::getNetwork(uid_t uid, unsigned requestedNetId, bool forDns) const {
    android::RWLock::AutoRLock lock(mRWLock);
    for (const UidEntry& entry : mUidMap) {
        if (entry.uidStart <= uid && uid <= entry.uidEnd) {
            if (forDns && !entry.forwardDns) {
                break;
            }
            return entry.netId;
        }
    }
    return getNetworkLocked(requestedNetId) ? requestedNetId : mDefaultNetId;
}

unsigned NetworkController::getNetworkId(const char* interface) const {
    android::RWLock::AutoRLock lock(mRWLock);
    for (const auto& entry : mPhysicalNetworks) {
        if (entry.second->hasInterface(interface)) {
            return entry.first;
        }
    }
    return NETID_UNSET;
}

bool NetworkController::isValidNetwork(unsigned netId) const {
    android::RWLock::AutoRLock lock(mRWLock);
    return getNetworkLocked(netId);
}

int NetworkController::createNetwork(unsigned netId, Permission permission) {
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
    mPhysicalNetworks[netId] = physicalNetwork;
    return 0;
}

int NetworkController::destroyNetwork(unsigned netId) {
    if (!isValidNetwork(netId)) {
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
        PhysicalNetwork* physicalNetwork = static_cast<PhysicalNetwork*>(network);
        if (int ret = physicalNetwork->removeAsDefault()) {
            ALOGE("inconceivable! removeAsDefault cannot fail on an empty network");
            return ret;
        }
        mDefaultNetId = NETID_UNSET;
    }
    mPhysicalNetworks.erase(netId);
    delete network;
    _resolv_delete_cache_for_net(netId);
    return 0;
}

int NetworkController::addInterfaceToNetwork(unsigned netId, const char* interface) {
    if (!isValidNetwork(netId)) {
        ALOGE("invalid netId %u", netId);
        return -EINVAL;
    }

    unsigned existingNetId = getNetworkId(interface);
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
    auto iter = mUsers.find(uid);
    return iter != mUsers.end() ? iter->second : PERMISSION_NONE;
}

void NetworkController::setPermissionForUsers(Permission permission,
                                              const std::vector<uid_t>& uids) {
    android::RWLock::AutoWLock lock(mRWLock);
    for (uid_t uid : uids) {
        if (permission == PERMISSION_NONE) {
            mUsers.erase(uid);
        } else {
            mUsers[uid] = permission;
        }
    }
}

bool NetworkController::isUserPermittedOnNetwork(uid_t uid, unsigned netId) const {
    android::RWLock::AutoRLock lock(mRWLock);
    auto userIter = mUsers.find(uid);
    Permission userPermission = (userIter != mUsers.end() ? userIter->second : PERMISSION_NONE);
    auto networkIter = mPhysicalNetworks.find(netId);
    if (networkIter == mPhysicalNetworks.end()) {
        return false;
    }
    Permission networkPermission = networkIter->second->getPermission();
    return (userPermission & networkPermission) == networkPermission;
}

int NetworkController::setPermissionForNetworks(Permission permission,
                                                const std::vector<unsigned>& netIds) {
    android::RWLock::AutoWLock lock(mRWLock);
    for (unsigned netId : netIds) {
        auto iter = mPhysicalNetworks.find(netId);
        if (iter == mPhysicalNetworks.end()) {
            ALOGE("invalid netId %u", netId);
            return -EINVAL;
        }

        // TODO: ioctl(SIOCKILLADDR, ...) to kill socets on the network that don't have permission.

        if (int ret = iter->second->setPermission(permission)) {
            return ret;
        }
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

Network* NetworkController::getNetworkLocked(unsigned netId) const {
    auto physicalNetworkIter = mPhysicalNetworks.find(netId);
    if (physicalNetworkIter != mPhysicalNetworks.end()) {
        return physicalNetworkIter->second;
    }
    return NULL;
}

int NetworkController::modifyRoute(unsigned netId, const char* interface, const char* destination,
                                   const char* nexthop, bool add, bool legacy, uid_t uid) {
    unsigned existingNetId = getNetworkId(interface);
    if (netId == NETID_UNSET || existingNetId != netId) {
        ALOGE("interface %s assigned to netId %u, not %u", interface, existingNetId, netId);
        return -ENOENT;
    }

    RouteController::TableType tableType;
    if (legacy) {
        if (getPermissionForUser(uid) & PERMISSION_CONNECTIVITY_INTERNAL) {
            tableType = RouteController::PRIVILEGED_LEGACY;
        } else {
            tableType = RouteController::LEGACY;
        }
    } else {
        tableType = RouteController::INTERFACE;
    }

    return add ? RouteController::addRoute(interface, destination, nexthop, tableType, uid) :
                 RouteController::removeRoute(interface, destination, nexthop, tableType, uid);
}

NetworkController::UidEntry::UidEntry(uid_t uidStart, uid_t uidEnd, unsigned netId,
                                      bool forwardDns) :
        uidStart(uidStart), uidEnd(uidEnd), netId(netId), forwardDns(forwardDns) {
}
