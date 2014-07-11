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

#ifndef NETD_SERVER_NETWORK_CONTROLLER_H
#define NETD_SERVER_NETWORK_CONTROLLER_H

#include "NetdConstants.h"
#include "Permission.h"

#include "utils/RWLock.h"

#include <list>
#include <map>
#include <set>
#include <sys/types.h>
#include <vector>

class Network;
class UidRanges;
class VirtualNetwork;

/*
 * Keeps track of default, per-pid, and per-uid-range network selection, as
 * well as the mark associated with each network. Networks are identified
 * by netid. In all set* commands netid == 0 means "unspecified" and is
 * equivalent to clearing the mapping.
 */
class NetworkController {
public:
    NetworkController();

    unsigned getDefaultNetwork() const;
    int setDefaultNetwork(unsigned netId) WARN_UNUSED_RESULT;

    // Order of preference: UID-specific, requestedNetId, default.
    // Specify NETID_UNSET for requestedNetId if the default network is preferred.
    // forDns indicates if we're querying the netId for a DNS request. This avoids sending DNS
    // requests to VPNs without DNS servers.
    unsigned getNetworkForUser(uid_t uid, unsigned requestedNetId, bool forDns) const;
    unsigned getNetworkForInterface(const char* interface) const;

    // TODO: Remove this hack.
    unsigned getNetIdForLocalNetwork() const;

    int createLocalNetwork(unsigned netId) WARN_UNUSED_RESULT;
    int createPhysicalNetwork(unsigned netId, Permission permission) WARN_UNUSED_RESULT;
    int createVirtualNetwork(unsigned netId, bool hasDns) WARN_UNUSED_RESULT;
    int destroyNetwork(unsigned netId) WARN_UNUSED_RESULT;

    int addInterfaceToNetwork(unsigned netId, const char* interface) WARN_UNUSED_RESULT;
    int removeInterfaceFromNetwork(unsigned netId, const char* interface) WARN_UNUSED_RESULT;

    Permission getPermissionForUser(uid_t uid) const;
    void setPermissionForUsers(Permission permission, const std::vector<uid_t>& uids);
    bool canUserSelectNetwork(uid_t uid, unsigned netId) const;
    int setPermissionForNetworks(Permission permission,
                                 const std::vector<unsigned>& netIds) WARN_UNUSED_RESULT;

    int addUsersToNetwork(unsigned netId, const UidRanges& uidRanges) WARN_UNUSED_RESULT;
    int removeUsersFromNetwork(unsigned netId, const UidRanges& uidRanges) WARN_UNUSED_RESULT;

    // Routes are added to tables determined by the interface, so only |interface| is actually used.
    // |netId| is given only to sanity check that the interface has the correct netId.
    int addRoute(unsigned netId, const char* interface, const char* destination,
                 const char* nexthop, bool legacy, uid_t uid) WARN_UNUSED_RESULT;
    int removeRoute(unsigned netId, const char* interface, const char* destination,
                    const char* nexthop, bool legacy, uid_t uid) WARN_UNUSED_RESULT;

    bool canProtect(uid_t uid) const;
    void allowProtect(const std::vector<uid_t>& uids);
    void denyProtect(const std::vector<uid_t>& uids);

private:
    bool isValidNetwork(unsigned netId) const;
    Network* getNetworkLocked(unsigned netId) const;
    VirtualNetwork* getVirtualNetworkForUserLocked(uid_t uid) const;
    Permission getPermissionForUserLocked(uid_t uid) const;

    int modifyRoute(unsigned netId, const char* interface, const char* destination,
                    const char* nexthop, bool add, bool legacy, uid_t uid) WARN_UNUSED_RESULT;

    // mRWLock guards all accesses to mDefaultNetId, mNetworks, mUsers and mProtectableUsers.
    mutable android::RWLock mRWLock;
    unsigned mDefaultNetId;
    std::map<unsigned, Network*> mNetworks;  // Map keys are NetIds.
    std::map<uid_t, Permission> mUsers;
    std::set<uid_t> mProtectableUsers;
};

#endif  // NETD_SERVER_NETWORK_CONTROLLER_H
