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

#include "Permission.h"
#include "utils/RWLock.h"

#include <list>
#include <map>
#include <set>
#include <stddef.h>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

class PermissionsController;
class RouteController;

/*
 * Keeps track of default, per-pid, and per-uid-range network selection, as
 * well as the mark associated with each network. Networks are identified
 * by netid. In all set* commands netid == 0 means "unspecified" and is
 * equivalent to clearing the mapping.
 */
class NetworkController {
public:
    NetworkController(PermissionsController* permissionsController,
                      RouteController* routeController);

    void clearNetworkPreference();
    unsigned getDefaultNetwork() const;
    bool setDefaultNetwork(unsigned netId);
    bool setNetworkForUidRange(int uid_start, int uid_end, unsigned netId, bool forward_dns);
    bool clearNetworkForUidRange(int uid_start, int uid_end, unsigned netId);

    // Order of preference: UID-specific, requested_netId, PID-specific, default.
    // Specify NETID_UNSET for requested_netId if the default network is preferred.
    // for_dns indicates if we're querrying the netId for a DNS request.  This avoids sending DNS
    // requests to VPNs without DNS servers.
    unsigned getNetwork(int uid, unsigned requested_netId, bool for_dns) const;

    unsigned getNetworkId(const char* interface) const;

    bool createNetwork(unsigned netId, Permission permission);
    bool destroyNetwork(unsigned netId);
    bool addInterfaceToNetwork(unsigned netId, const char* interface);
    bool removeInterfaceFromNetwork(unsigned netId, const char* interface);

    bool setPermissionForUser(Permission permission, const std::vector<unsigned>& uid);
    bool setPermissionForNetwork(Permission permission, const std::vector<unsigned>& netId);

    // Routes are added to tables determined by the interface, so only |interface| is actually used.
    // |netId| is given only to sanity check that the interface has the correct netId.
    int addRoute(unsigned netId, const char* interface, const char* destination,
                 const char* nexthop, bool legacy, unsigned uid);
    int removeRoute(unsigned netId, const char* interface, const char* destination,
                    const char* nexthop, bool legacy, unsigned uid);

    bool isValidNetwork(unsigned netId) const;

private:
    typedef std::multimap<unsigned, std::string>::const_iterator InterfaceIteratorConst;
    typedef std::multimap<unsigned, std::string>::iterator InterfaceIterator;
    typedef std::pair<InterfaceIterator, InterfaceIterator> InterfaceRange;

    int modifyRoute(unsigned netId, const char* interface, const char* destination,
                    const char* nexthop, bool add, bool legacy, unsigned uid);

    struct UidEntry {
        int uid_start;
        int uid_end;
        unsigned netId;
        bool forward_dns;
        UidEntry(int uid_start, int uid_end, unsigned netId, bool forward_dns);
    };

    // mRWLock guards all accesses to mUidMap, mDefaultNetId and mValidNetworks.
    mutable android::RWLock mRWLock;
    std::list<UidEntry> mUidMap;
    unsigned mDefaultNetId;
    std::set<unsigned> mValidNetworks;

    PermissionsController* const mPermissionsController;
    RouteController* const mRouteController;

    // Maps a netId to all its interfaces.
    //
    // We need to know interface names to configure incoming packet marking and because routing
    // tables are associated with interfaces and not with netIds.
    //
    // An interface may belong to at most one netId, but a netId may have multiple interfaces.
    std::multimap<unsigned, std::string> mNetIdToInterfaces;
};

#endif  // NETD_SERVER_NETWORK_CONTROLLER_H
