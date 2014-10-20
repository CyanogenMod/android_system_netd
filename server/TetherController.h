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

#define INVALID_TABLE_NUMBER -1

typedef android::netd::List<char *> InterfaceCollection;
typedef android::netd::List<struct in_addr> NetAddressCollection;

class TetherController {
    InterfaceCollection  *mInterfaces;
    // NetId to use for forwarded DNS queries. This may not be the default
    // network, e.g., in the case where we are tethering to a DUN APN.
    unsigned              mDnsNetId;
    NetAddressCollection *mDnsForwarders;
    pid_t                 mDaemonPid;
    int                   mDaemonFd;
    pid_t                 mRtrAdvPid; // IPv6 support
    InterfaceCollection  *mUpstreamInterfaces;

public:
    TetherController();
    virtual ~TetherController();

    int setIpFwdEnabled(bool enable);
    bool getIpFwdEnabled();

    int startTethering(int num_addrs, struct in_addr* addrs);

    int stopTethering();
    bool isTetheringStarted();

    unsigned getDnsNetId();
    int setDnsForwarders(unsigned netId, char **servers, int numServers);
    NetAddressCollection *getDnsForwarders();

    int tetherInterface(const char *interface);
    int untetherInterface(const char *interface);
    InterfaceCollection *getTetheredInterfaceList();
    int startV6RtrAdv(int num_ifaces, char **ifaces, int table_number);
    int stopV6RtrAdv();
    bool isV6RtrAdvStarted();
    int configureV6RtrAdv();
    int addUpstreamInterface(char *iface);
    int removeUpstreamInterface(char *iface);

private:
    int applyDnsInterfaces();
    int getIfaceIndexForIface(const char *iface);
};

#endif
