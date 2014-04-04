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

#ifndef _SECONDARY_TABLE_CONTROLLER_H
#define _SECONDARY_TABLE_CONTROLLER_H

#include <map>

#include <sysutils/FrameworkListener.h>

#include <net/if.h>
#include "NetdConstants.h"
#include "NetworkController.h"

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

static const int BASE_TABLE_NUMBER = 60;
static const char *EXEMPT_PRIO = "99";
static const char *RULE_PRIO = "100";

// SecondaryTableController is responsible for maintaining the "secondary" routing tables, where
// "secondary" means not the main table.  The "secondary" tables are used for VPNs.
class SecondaryTableController {

public:
    SecondaryTableController(NetworkController* controller);
    virtual ~SecondaryTableController();

    // Add/remove a particular route in a particular interface's table.
    int addRoute(SocketClient *cli, char *iface, char *dest, int prefixLen, char *gateway);
    int removeRoute(SocketClient *cli, char *iface, char *dest, int prefixLen, char *gateway);

    int modifyFromRule(unsigned netId, const char *action, const char *addr);
    int modifyLocalRoute(unsigned netId, const char *action, const char *iface, const char *addr);

    // Add/remove rules to force packets in a particular range of UIDs over a particular interface.
    // This is accomplished with a rule specifying these UIDs use the interface's routing chain.
    int addUidRule(const char *iface, int uid_start, int uid_end);
    int removeUidRule(const char *iface, int uid_start, int uid_end);

    // Add/remove rules and chains so packets intended for a particular interface use that
    // interface.
    int addFwmarkRule(const char *iface);
    int removeFwmarkRule(const char *iface);

    // Add/remove rules so packets going to a particular range of IPs use a particular interface.
    // This is accomplished by adding/removeing a rule to/from an interface’s chain to mark packets
    // destined for the IP address range with the mark for the interface’s table.
    int addFwmarkRoute(const char* iface, const char *dest, int prefix);
    int removeFwmarkRoute(const char* iface, const char *dest, int prefix);

    // Add/remove rules so packets going to a particular IP address use the main table (i.e. not
    // the VPN tables).  This is used in conjunction with adding a specific route to the main
    // table.  This is to support requestRouteToHost().
    // This is accomplished by marking these packets with the protect mark and adding a rule to
    // use the main table.
    int addHostExemption(const char *host);
    int removeHostExemption(const char *host);

    void getUidMark(SocketClient *cli, int uid);
    void getProtectMark(SocketClient *cli);

    int setupIptablesHooks();

    static const char* LOCAL_MANGLE_OUTPUT;
    static const char* LOCAL_MANGLE_POSTROUTING;
    static const char* LOCAL_NAT_POSTROUTING;


private:
    NetworkController *mNetCtrl;

    int setUidRule(const char* iface, int uid_start, int uid_end, bool add);
    int setFwmarkRule(const char *iface, bool add);
    int setFwmarkRoute(const char* iface, const char *dest, int prefix, bool add);
    int setHostExemption(const char *host, bool add);
    int modifyRoute(SocketClient *cli, const char *action, char *iface, char *dest, int prefix,
            char *gateway, unsigned netId);

    std::map<unsigned, int> mNetIdRuleCount;
    void modifyRuleCount(unsigned netId, const char *action);
    const char *getVersion(const char *addr);
    IptablesTarget getIptablesTarget(const char *addr);

    int runCmd(int argc, const char **argv);
};

#endif
