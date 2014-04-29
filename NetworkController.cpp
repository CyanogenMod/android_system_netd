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

// Mark 1 is reserved for SecondaryTableController::PROTECT_MARK.
NetworkController::NetworkController()
        : mDefaultNetId(NETID_UNSET),
          mNextFreeNetId(10) {}

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
    if (uid_start > uid_end || netId == NETID_UNSET)
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
    if (uid_start > uid_end || netId == NETID_UNSET)
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
    if (requested_netId != NETID_UNSET)
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

NetworkController::UidEntry::UidEntry(
    int start, int end, unsigned netId, bool forward_dns)
      : uid_start(start),
        uid_end(end),
        netId(netId),
        forward_dns(forward_dns) {
}
