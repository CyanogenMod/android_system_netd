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
        : mDefaultNetId(NETID_UNSET),
          mNextFreeNetId(MIN_NET_ID),
          mPermissionsController(permissionsController),
          mRouteController(routeController) {
}

void NetworkController::clearNetworkPreference() {
    android::RWLock::AutoWLock lock(mRWLock);
    mUidMap.clear();
    mPidMap.clear();
}

unsigned NetworkController::getDefaultNetwork() const {
    return mDefaultNetId;
}

void NetworkController::setDefaultNetwork(unsigned netId) {
    android::RWLock::AutoWLock lock(mRWLock);
    mDefaultNetId = netId;
}

void NetworkController::setNetworkForPid(int pid, unsigned netId) {
    android::RWLock::AutoWLock lock(mRWLock);
    if (netId == 0) {
        mPidMap.erase(pid);
    } else {
        mPidMap[pid] = netId;
    }
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

unsigned NetworkController::getNetwork(int uid, unsigned requested_netId, int pid,
        bool for_dns) const {
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
    if (pid != PID_UNSPECIFIED) {
        std::map<int, unsigned>::const_iterator it = mPidMap.find(pid);
        if (it != mPidMap.end())
            return it->second;
    }
    return mDefaultNetId;
}

unsigned NetworkController::getNetworkId(const char* interface) {
    std::map<std::string, unsigned>::const_iterator it = mIfaceNetidMap.find(interface);
    if (it != mIfaceNetidMap.end())
        return it->second;

    unsigned netId = mNextFreeNetId++;
    mIfaceNetidMap[interface] = netId;
    return netId;
}

bool NetworkController::createNetwork(unsigned netId, const char* interface,
                                      Permission permission) {
    if (!isNetIdValid(netId) || !interface) {
        ALOGE("invalid netId %u or interface null", netId);
        return false;
    }

    typedef std::multimap<unsigned, std::string>::const_iterator Iterator;
    for (Iterator iter = mNetIdToInterfaces.begin(); iter != mNetIdToInterfaces.end(); ++iter) {
        if (iter->second == interface) {
            ALOGE("interface %s already assigned to netId %u", interface, iter->first);
            return false;
        }
    }

    if (!mRouteController->createNetwork(netId, interface, permission)) {
        return false;
    }

    mPermissionsController->setPermissionForNetwork(permission, netId);
    mNetIdToInterfaces.insert(std::pair<unsigned, std::string>(netId, interface));
    return true;
}

bool NetworkController::destroyNetwork(unsigned netId) {
    if (!isNetIdValid(netId)) {
        ALOGE("invalid netId %u", netId);
        return false;
    }

    // TODO: ioctl(SIOCKILLADDR, ...) to kill all sockets on the old network.

    bool status = true;

    Permission permission = mPermissionsController->getPermissionForNetwork(netId);

    typedef std::multimap<unsigned, std::string>::const_iterator Iterator;
    std::pair<Iterator, Iterator> range = mNetIdToInterfaces.equal_range(netId);
    for (Iterator iter = range.first; iter != range.second; ++iter) {
        if (!mRouteController->destroyNetwork(netId, iter->second.c_str(), permission)) {
            status = false;
        }
    }

    mPermissionsController->setPermissionForNetwork(PERMISSION_NONE, netId);
    mNetIdToInterfaces.erase(netId);

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

        typedef std::multimap<unsigned, std::string>::const_iterator Iterator;
        std::pair<Iterator, Iterator> range = mNetIdToInterfaces.equal_range(netId[i]);
        if (range.first == range.second) {
            ALOGE("unknown netId %u", netId[i]);
            status = false;
            continue;
        }

        Permission oldPermission = mPermissionsController->getPermissionForNetwork(netId[i]);
        if (oldPermission == newPermission) {
            continue;
        }

        // TODO: ioctl(SIOCKILLADDR, ...) to kill sockets on the network that don't have
        // newPermission.

        for (Iterator iter = range.first; iter != range.second; ++iter) {
            if (!mRouteController->modifyNetworkPermission(netId[i], iter->second.c_str(),
                                                           oldPermission, newPermission)) {
                status = false;
            }
        }

        mPermissionsController->setPermissionForNetwork(newPermission, netId[i]);
    }

    return status;
}

NetworkController::UidEntry::UidEntry(
    int start, int end, unsigned netId, bool forward_dns)
      : uid_start(start),
        uid_end(end),
        netId(netId),
        forward_dns(forward_dns) {
}
