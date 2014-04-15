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

#ifndef _NETD_NETWORKCONTROLLER_H
#define _NETD_NETWORKCONTROLLER_H

#include "Permission.h"

#include <list>
#include <map>
#include <string>
#include <vector>

#include <stddef.h>
#include <stdint.h>
#include <utils/RWLock.h>

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
    enum {
        // For use with getNetwork().
        PID_UNSPECIFIED = 0,
    };

    static bool isNetIdValid(unsigned netId);

    NetworkController(PermissionsController* permissionsController,
                      RouteController* routeController);

    void clearNetworkPreference();
    unsigned getDefaultNetwork() const;
    bool setDefaultNetwork(unsigned netId);
    void setNetworkForPid(int pid, unsigned netId);
    bool setNetworkForUidRange(int uid_start, int uid_end, unsigned netId, bool forward_dns);
    bool clearNetworkForUidRange(int uid_start, int uid_end, unsigned netId);

    // Order of preference: UID-specific, requested_netId, PID-specific, default.
    // Specify NETID_UNSET for requested_netId if the default network is preferred.
    // Specify PID_UNSPECIFIED for pid to ignore PID-specific overrides.
    // for_dns indicates if we're querrying the netId for a DNS request.  This avoids sending DNS
    // requests to VPNs without DNS servers.
    unsigned getNetwork(int uid, unsigned requested_netId, int pid, bool for_dns) const;

    unsigned getNetworkId(const char* interface);

    bool createNetwork(unsigned netId, const char* interface, Permission permission);
    bool destroyNetwork(unsigned netId);

    bool setPermissionForUser(Permission permission, const std::vector<unsigned>& uid);
    bool setPermissionForNetwork(Permission permission, const std::vector<unsigned>& netId);

    // Routes are added to tables determined by the interface, so only |interface| is actually used.
    // |netId| is given only to sanity check that the interface has the correct netId.
    bool addRoute(unsigned netId, const char* interface, const char* destination,
                  const char* nexthop);
    bool removeRoute(unsigned netId, const char* interface, const char* destination,
                     const char* nexthop);

private:
    typedef std::multimap<unsigned, std::string>::const_iterator InterfaceIterator;
    typedef std::pair<InterfaceIterator, InterfaceIterator> InterfaceRange;

    // Returns the netId that |interface| belongs to, or NETID_UNSET if it doesn't belong to any.
    unsigned netIdForInterface(const char* interface);

    // Returns the interfaces assigned to |netId|. Sets |*status| to false if there are none.
    InterfaceRange interfacesForNetId(unsigned netId, bool* status);

    bool modifyRoute(unsigned netId, const char* interface, const char* destination,
                     const char* nexthop, bool add);

    struct UidEntry {
        int uid_start;
        int uid_end;
        unsigned netId;
        bool forward_dns;
        UidEntry(int uid_start, int uid_end, unsigned netId, bool forward_dns);
    };

    mutable android::RWLock mRWLock;
    std::list<UidEntry> mUidMap;
    std::map<int, unsigned> mPidMap;
    unsigned mDefaultNetId;

    std::map<std::string, unsigned> mIfaceNetidMap;
    unsigned mNextFreeNetId;

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

#endif
