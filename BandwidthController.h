/*
 * Copyright (C) 2011 The Android Open Source Project
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
#ifndef _BANDWIDTH_CONTROLLER_H
#define _BANDWIDTH_CONTROLLER_H

#include <list>
#include <string>
#include <utility>  // for pair
class BandwidthController {
public:
    BandwidthController();
    int enableBandwidthControl(void);
    int disableBandwidthControl(void);

    int setInterfaceSharedQuota(int64_t bytes, const char *iface);
    int removeInterfaceSharedQuota(const char *iface);

    int addNaughtyApps(int numUids, char *appUids[]);
    int removeNaughtyApps(int numUids, char *appUids[]);

protected:
    int runCommands(int numCommands, const char *commands[],
            bool allowFailure = false, bool isIpv6 = false);
    typedef std::pair<std::string /*ifaceName*/, int64_t /*quota*/> QuotaInfo;
    enum IptOp {IptOpInsert, IptOpReplace, IptOpDelete};
    int64_t sharedQuotaBytes;
    std::list<QuotaInfo> ifaceRules;
    std::list<int /*appUid*/> naughtyAppUids;
    std::string makeIptablesNaughtyCmd(IptOp op, int uid, bool isIp6);
    std::string makeIptablesQuotaCmd(IptOp op, char *costName, int64_t quota, bool isIp6);
    int maninpulateNaughtyApps(int numUids, char *appStrUids[], bool doAdd);

private:
    static const char *cleanupCommands[];
    static const char *setupCommands[];
    static const char *basicAccountingCommands[];
    static const int MAX_CMD_LEN;
    static const int MAX_IFACENAME_LEN;
    static const int MAX_CMD_ARGS;
    static const char IPTABLES_PATH[];
    static const char IP6TABLES_PATH[];

    static int runIptablesCmd(const char *cmd, bool isIp6 = false);
};

#endif
