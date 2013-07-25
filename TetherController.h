/*
 * Copyright (C) 2008 The Android Open Source Project
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

#ifndef _TETHER_CONTROLLER_H
#define _TETHER_CONTROLLER_H

#include <netinet/in.h>

#include "List.h"

#define HOUR 3600

/* Keep this in sync with packages/apps/Settings/res/values/arrays.xml's
 * tethering_lease_time_entries/values */
#define DEFAULT_LEASE_TIME (1*HOUR)

typedef android::netd::List<char *> InterfaceCollection;
typedef android::netd::List<struct in_addr> NetAddressCollection;

class TetherController {
    InterfaceCollection  *mInterfaces;
    NetAddressCollection *mDnsForwarders;
    pid_t                 mDaemonPid;
    int                   mDaemonFd;

public:
    TetherController();
    virtual ~TetherController();

    int setIpFwdEnabled(bool enable);
    bool getIpFwdEnabled();

    int startTethering(int num_addrs, struct in_addr* addrs, int lease_time=DEFAULT_LEASE_TIME);

    int stopTethering();
    bool isTetheringStarted();

    int setDnsForwarders(char **servers, int numServers);
    NetAddressCollection *getDnsForwarders();

    int tetherInterface(const char *interface);
    int untetherInterface(const char *interface);
    InterfaceCollection *getTetheredInterfaceList();

private:
    int applyDnsInterfaces();
};

#endif
