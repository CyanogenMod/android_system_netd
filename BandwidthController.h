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
    class TetherStats {
    public:
        TetherStats(void)
                : rxBytes(-1), rxPackets(-1),
                    txBytes(-1), txPackets(-1) {};
        TetherStats(std::string ifnIn, std::string ifnOut,
                int64_t rxB, int64_t rxP,
                int64_t txB, int64_t txP)
                        : ifaceIn(ifnIn), ifaceOut(ifnOut),
                            rxBytes(rxB), rxPackets(rxP),
                    txBytes(txB), txPackets(txP) {};
        std::string ifaceIn;
        std::string ifaceOut;
        int64_t rxBytes, rxPackets;
        int64_t txBytes, txPackets;
        /*
         * Allocates a new string representing this:
         * ifaceIn ifaceOut rx_bytes rx_packets tx_bytes tx_packets
         * The caller is responsible for free()'ing the returned ptr.
         */
        char *getStatsLine(void);
    };

    BandwidthController();
    int enableBandwidthControl(void);
    int disableBandwidthControl(void);

    int setInterfaceSharedQuota(const char *iface, int64_t bytes);
    int getInterfaceSharedQuota(int64_t *bytes);
    int removeInterfaceSharedQuota(const char *iface);

    int setInterfaceQuota(const char *iface, int64_t bytes);
    int getInterfaceQuota(const char *iface, int64_t *bytes);
    int removeInterfaceQuota(const char *iface);

    int addNaughtyApps(int numUids, char *appUids[]);
    int removeNaughtyApps(int numUids, char *appUids[]);

    int setGlobalAlert(int64_t bytes);
    int removeGlobalAlert(void);
    int setGlobalAlertInForwardChain(void);
    int removeGlobalAlertInForwardChain(void);

    int setSharedAlert(int64_t bytes);
    int removeSharedAlert(void);

    int setInterfaceAlert(const char *iface, int64_t bytes);
    int removeInterfaceAlert(const char *iface);

    /*
     * stats should have ifaceIn and ifaceOut initialized.
     * Byte counts should be left to the default (-1).
     */
    int getTetherStats(TetherStats &stats);

protected:
    class QuotaInfo {
    public:
      QuotaInfo(std::string ifn, int64_t q, int64_t a)
              : ifaceName(ifn), quota(q), alert(a) {};
        std::string ifaceName;
        int64_t quota;
        int64_t alert;
    };

    enum IptIpVer { IptIpV4, IptIpV6 };
    enum IptOp { IptOpInsert, IptOpReplace, IptOpDelete };
    enum IptRejectOp { IptRejectAdd, IptRejectNoAdd };
    enum NaughtyAppOp { NaughtyAppOpAdd, NaughtyAppOpRemove };
    enum QuotaType { QuotaUnique, QuotaShared };
    enum RunCmdErrHandling { RunCmdFailureBad, RunCmdFailureOk };

    int maninpulateNaughtyApps(int numUids, char *appStrUids[], NaughtyAppOp appOp);

    int prepCostlyIface(const char *ifn, QuotaType quotaType);
    int cleanupCostlyIface(const char *ifn, QuotaType quotaType);

    std::string makeIptablesNaughtyCmd(IptOp op, int uid);
    std::string makeIptablesQuotaCmd(IptOp op, const char *costName, int64_t quota);

    int runIptablesAlertCmd(IptOp op, const char *alertName, int64_t bytes);
    int runIptablesAlertFwdCmd(IptOp op, const char *alertName, int64_t bytes);

    /* Runs for both ipv4 and ipv6 iptables */
    int runCommands(int numCommands, const char *commands[], RunCmdErrHandling cmdErrHandling);
    /* Runs for both ipv4 and ipv6 iptables, appends -j REJECT --reject-with ...  */
    static int runIpxtablesCmd(const char *cmd, IptRejectOp rejectHandling);
    static int runIptablesCmd(const char *cmd, IptRejectOp rejectHandling, IptIpVer iptIpVer);

    // Provides strncpy() + check overflow.
    static int StrncpyAndCheck(char *buffer, const char *src, size_t buffSize);

    int updateQuota(const char *alertName, int64_t bytes);

    int setCostlyAlert(const char *costName, int64_t bytes, int64_t *alertBytes);
    int removeCostlyAlert(const char *costName, int64_t *alertBytes);

    /*
     * stats should have ifaceIn and ifaceOut initialized.
     * fp should be a file to the FORWARD rules of iptables.
     */
    static int parseForwardChainStats(TetherStats &stats, FILE *fp);

    /*------------------*/

    std::list<std::string> sharedQuotaIfaces;
    int64_t sharedQuotaBytes;
    int64_t sharedAlertBytes;
    int64_t globalAlertBytes;
    /*
     * This tracks the number of tethers setup.
     * The FORWARD chain is updated in the following cases:
     *  - The 1st time a globalAlert is setup and there are tethers setup.
     *  - Anytime a globalAlert is removed and there are tethers setup.
     *  - The 1st tether is setup and there is a globalAlert active.
     *  - The last tether is removed and there is a globalAlert active.
     */
    int globalAlertTetherCount;

    std::list<QuotaInfo> quotaIfaces;
    std::list<int /*appUid*/> naughtyAppUids;

private:
    static const char *IPT_CLEANUP_COMMANDS[];
    static const char *IPT_SETUP_COMMANDS[];
    static const char *IPT_BASIC_ACCOUNTING_COMMANDS[];

    /* Alphabetical */
    static const char ALERT_IPT_TEMPLATE[];
    static const int  ALERT_RULE_POS_IN_COSTLY_CHAIN;
    static const char ALERT_GLOBAL_NAME[];
    static const char IP6TABLES_PATH[];
    static const char IPTABLES_PATH[];
    static const int  MAX_CMD_ARGS;
    static const int  MAX_CMD_LEN;
    static const int  MAX_IFACENAME_LEN;
    static const int  MAX_IPT_OUTPUT_LINE_LEN;

    /*
     * When false, it will directly use system() instead of logwrap()
     */
    static bool useLogwrapCall;
};

#endif
