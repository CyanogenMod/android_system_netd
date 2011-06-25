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

    int setInterfaceSharedQuota(const char *iface, int64_t bytes);
    int removeInterfaceSharedQuota(const char *iface);

    int setInterfaceQuota(const char *iface, int64_t bytes);
    int removeInterfaceQuota(const char *iface);

    int addNaughtyApps(int numUids, char *appUids[]);
    int removeNaughtyApps(int numUids, char *appUids[]);


protected:
    typedef std::pair<std::string /*ifaceName*/, int64_t /*quota*/> QuotaInfo;
    enum IptIpVer { IptIpV4, IptIpV6 };
    enum IptOp { IptOpInsert, IptOpReplace, IptOpDelete };
    enum IptRejectOp { IptRejectAdd, IptRejectNoAdd };
    enum NaughtyAppOp { NaughtyAppOpAdd, NaughtyAppOpRemove };
    enum QuotaType { QuotaUnique, QuotaShared };
    enum RunCmdErrHandling { RunCmdFailureBad, RunCmdFailureOk };

    int64_t sharedQuotaBytes;
    std::list<std::string> sharedQuotaIfaces;

    std::list<QuotaInfo> quotaIfaces;

    std::list<int /*appUid*/> naughtyAppUids;
    int maninpulateNaughtyApps(int numUids, char *appStrUids[], NaughtyAppOp appOp);

    int prepCostlyIface(const char *ifn, QuotaType quotaType);
    int cleanupCostlyIface(const char *ifn, QuotaType quotaType);

    std::string makeIptablesNaughtyCmd(IptOp op, int uid);
    std::string makeIptablesQuotaCmd(IptOp op, const char *costName, int64_t quota);

    /* Runs for both ipv4 and ipv6 iptables */
    int runCommands(int numCommands, const char *commands[], RunCmdErrHandling cmdErrHandling);
    /* Runs for both ipv4 and ipv6 iptables, appends -j REJECT --reject-with ...  */
    static int runIpxtablesCmd(const char *cmd, IptRejectOp rejectHandling);
    static int runIptablesCmd(const char *cmd, IptRejectOp rejectHandling, IptIpVer iptIpVer);

    // Provides strncpy() + check overflow.
    static int StrncpyAndCheck(char *buffer, const char *src, size_t buffSize);

private:
    static const char *cleanupCommands[];
    static const char *setupCommands[];
    static const char *basicAccountingCommands[];
    static const int MAX_CMD_LEN;
    static const int MAX_IFACENAME_LEN;
    static const int MAX_CMD_ARGS;
    static const char IPTABLES_PATH[];
    static const char IP6TABLES_PATH[];

};

#endif
