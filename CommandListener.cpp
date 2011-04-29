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

#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>

#include <linux/if.h>

#define LOG_TAG "CommandListener"
#include <cutils/log.h>

#include <sysutils/SocketClient.h>

#include "CommandListener.h"
#include "ResponseCode.h"
#include "ThrottleController.h"


extern "C" int ifc_init(void);
extern "C" int ifc_get_hwaddr(const char *name, void *ptr);
extern "C" int ifc_get_info(const char *name, in_addr_t *addr, in_addr_t *mask, unsigned *flags);
extern "C" int ifc_set_addr(const char *name, in_addr_t addr);
extern "C" int ifc_set_mask(const char *name, in_addr_t mask);
extern "C" int ifc_up(const char *name);
extern "C" int ifc_down(const char *name);

TetherController *CommandListener::sTetherCtrl = NULL;
NatController *CommandListener::sNatCtrl = NULL;
PppController *CommandListener::sPppCtrl = NULL;
PanController *CommandListener::sPanCtrl = NULL;
SoftapController *CommandListener::sSoftapCtrl = NULL;
UsbController *CommandListener::sUsbCtrl = NULL;
ResolverController *CommandListener::sResolverCtrl = NULL;

CommandListener::CommandListener() :
                 FrameworkListener("netd") {
    registerCmd(new InterfaceCmd());
    registerCmd(new IpFwdCmd());
    registerCmd(new TetherCmd());
    registerCmd(new NatCmd());
    registerCmd(new ListTtysCmd());
    registerCmd(new PppdCmd());
    registerCmd(new PanCmd());
    registerCmd(new SoftapCmd());
    registerCmd(new UsbCmd());
    registerCmd(new ResolverCmd());

    if (!sTetherCtrl)
        sTetherCtrl = new TetherController();
    if (!sNatCtrl)
        sNatCtrl = new NatController();
    if (!sPppCtrl)
        sPppCtrl = new PppController();
    if (!sPanCtrl)
        sPanCtrl = new PanController();
    if (!sSoftapCtrl)
        sSoftapCtrl = new SoftapController();
    if (!sUsbCtrl)
        sUsbCtrl = new UsbController();
    if (!sResolverCtrl)
        sResolverCtrl = new ResolverController();
}

CommandListener::InterfaceCmd::InterfaceCmd() :
                 NetdCommand("interface") {
}

int CommandListener::InterfaceCmd::runCommand(SocketClient *cli,
                                                      int argc, char **argv) {
    if (argc < 2) {
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Missing argument", false);
        return 0;
    }

    if (!strcmp(argv[1], "list")) {
        DIR *d;
        struct dirent *de;

        if (!(d = opendir("/sys/class/net"))) {
            cli->sendMsg(ResponseCode::OperationFailed, "Failed to open sysfs dir", true);
            return 0;
        }

        while((de = readdir(d))) {
            if (de->d_name[0] == '.')
                continue;
            cli->sendMsg(ResponseCode::InterfaceListResult, de->d_name, false);
        }
        closedir(d);
        cli->sendMsg(ResponseCode::CommandOkay, "Interface list completed", false);
        return 0;
    } else if (!strcmp(argv[1], "readrxcounter")) {
        if (argc != 3) {
            cli->sendMsg(ResponseCode::CommandSyntaxError,
                    "Usage: interface readrxcounter <interface>", false);
            return 0;
        }
        unsigned long rx = 0, tx = 0;
        if (readInterfaceCounters(argv[2], &rx, &tx)) {
            cli->sendMsg(ResponseCode::OperationFailed, "Failed to read counters", true);
            return 0;
        }

        char *msg;
        asprintf(&msg, "%lu", rx);
        cli->sendMsg(ResponseCode::InterfaceRxCounterResult, msg, false);
        free(msg);

        return 0;
    } else if (!strcmp(argv[1], "readtxcounter")) {
        if (argc != 3) {
            cli->sendMsg(ResponseCode::CommandSyntaxError,
                    "Usage: interface readtxcounter <interface>", false);
            return 0;
        }
        unsigned long rx = 0, tx = 0;
        if (readInterfaceCounters(argv[2], &rx, &tx)) {
            cli->sendMsg(ResponseCode::OperationFailed, "Failed to read counters", true);
            return 0;
        }

        char *msg = NULL;
        asprintf(&msg, "%lu", tx);
        cli->sendMsg(ResponseCode::InterfaceTxCounterResult, msg, false);
        free(msg);
        return 0;
    } else if (!strcmp(argv[1], "getthrottle")) {
        if (argc != 4 || (argc == 4 && (strcmp(argv[3], "rx") && (strcmp(argv[3], "tx"))))) {
            cli->sendMsg(ResponseCode::CommandSyntaxError,
                    "Usage: interface getthrottle <interface> <rx|tx>", false);
            return 0;
        }
        int val = 0;
        int rc = 0;
        int voldRc = ResponseCode::InterfaceRxThrottleResult;

        if (!strcmp(argv[3], "rx")) {
            rc = ThrottleController::getInterfaceRxThrottle(argv[2], &val);
        } else {
            rc = ThrottleController::getInterfaceTxThrottle(argv[2], &val);
            voldRc = ResponseCode::InterfaceTxThrottleResult;
        }
        if (rc) {
            cli->sendMsg(ResponseCode::OperationFailed, "Failed to get throttle", true);
        } else {
            char *msg = NULL;
            asprintf(&msg, "%u", val);
            cli->sendMsg(voldRc, msg, false);
            free(msg);
            return 0;
        }
        return 0;
    } else if (!strcmp(argv[1], "setthrottle")) {
        if (argc != 5) {
            cli->sendMsg(ResponseCode::CommandSyntaxError,
                    "Usage: interface setthrottle <interface> <rx_kbps> <tx_kbps>", false);
            return 0;
        }
        if (ThrottleController::setInterfaceThrottle(argv[2], atoi(argv[3]), atoi(argv[4]))) {
            cli->sendMsg(ResponseCode::OperationFailed, "Failed to set throttle", true);
        } else {
            cli->sendMsg(ResponseCode::CommandOkay, "Interface throttling set", false);
        }
        return 0;
    } else {
        /*
         * These commands take a minimum of 3 arguments
         */
        if (argc < 3) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "Missing argument", false);
            return 0;
        }
        if (!strcmp(argv[1], "getcfg")) {
            struct in_addr addr, mask;
            unsigned char hwaddr[6];
            unsigned flags = 0;

            ifc_init();
            memset(hwaddr, 0, sizeof(hwaddr));

            if (ifc_get_info(argv[2], &addr.s_addr, &mask.s_addr, &flags)) {
                cli->sendMsg(ResponseCode::OperationFailed, "Interface not found", true);
                return 0;
            }

            if (ifc_get_hwaddr(argv[2], (void *) hwaddr)) {
                LOGW("Failed to retrieve HW addr for %s (%s)", argv[2], strerror(errno));
            }

            char *addr_s = strdup(inet_ntoa(addr));
            char *mask_s = strdup(inet_ntoa(mask));
            const char *updown, *brdcst, *loopbk, *ppp, *running, *multi;

            updown =  (flags & IFF_UP)           ? "up" : "down";
            brdcst =  (flags & IFF_BROADCAST)    ? " broadcast" : "";
            loopbk =  (flags & IFF_LOOPBACK)     ? " loopback" : "";
            ppp =     (flags & IFF_POINTOPOINT)  ? " point-to-point" : "";
            running = (flags & IFF_RUNNING)      ? " running" : "";
            multi =   (flags & IFF_MULTICAST)    ? " multicast" : "";

            char *flag_s;

            asprintf(&flag_s, "[%s%s%s%s%s%s]", updown, brdcst, loopbk, ppp, running, multi);

            char *msg = NULL;
            asprintf(&msg, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x %s %s %s",
                     hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5],
                     addr_s, mask_s, flag_s);

            cli->sendMsg(ResponseCode::InterfaceGetCfgResult, msg, false);

            free(addr_s);
            free(mask_s);
            free(flag_s);
            free(msg);
            return 0;
        } else if (!strcmp(argv[1], "setcfg")) {
            // arglist: iface addr mask [flags]
            if (argc < 5) {
                cli->sendMsg(ResponseCode::CommandSyntaxError, "Missing argument", false);
                return 0;
            }
            LOGD("Setting iface cfg");

            struct in_addr addr, mask;
            unsigned flags = 0;

            if (!inet_aton(argv[3], &addr)) {
                cli->sendMsg(ResponseCode::CommandParameterError, "Invalid address", false);
                return 0;
            }

            if (!inet_aton(argv[4], &mask)) {
                cli->sendMsg(ResponseCode::CommandParameterError, "Invalid netmask", false);
                return 0;
            }

            ifc_init();
            if (ifc_set_addr(argv[2], addr.s_addr)) {
                cli->sendMsg(ResponseCode::OperationFailed, "Failed to set address", true);
                return 0;
            }

            if (ifc_set_mask(argv[2], mask.s_addr)) {
                cli->sendMsg(ResponseCode::OperationFailed, "Failed to set netmask", true);
                return 0;
            }

            /* Process flags */
            /* read from "[XX" arg to "YY]" arg */
            bool bStarted = false;
            for (int i = 5; i < argc; i++) {
                char *flag = argv[i];
                if (!bStarted) {
                    if (*flag == '[') {
                        flag++;
                        bStarted = true;
                    } else {
                        continue;
                    }
                }
                int len = strlen(flag);
                if (flag[len-1] == ']') {
                    i = argc;  // stop after this loop
                    flag[len-1] = 0;
                }
                if (!strcmp(flag, "up")) {
                    LOGD("Trying to bring up %s", argv[2]);
                    if (ifc_up(argv[2])) {
                        LOGE("Error upping interface");
                        cli->sendMsg(ResponseCode::OperationFailed, "Failed to up interface", true);
                        return 0;
                    }
                } else if (!strcmp(flag, "down")) {
                    LOGD("Trying to bring down %s", argv[2]);
                    if (ifc_down(argv[2])) {
                        LOGE("Error downing interface");
                        cli->sendMsg(ResponseCode::OperationFailed, "Failed to down interface", true);
                        return 0;
                    }
                } else if (!strcmp(flag, "broadcast")) {
                    LOGD("broadcast flag ignored");
                } else if (!strcmp(flag, "multicast")) {
                    LOGD("multicast flag ignored");
                } else {
                    cli->sendMsg(ResponseCode::CommandParameterError, "Flag unsupported", false);
                    return 0;
                }
            }
            cli->sendMsg(ResponseCode::CommandOkay, "Interface configuration set", false);
            return 0;
        } else {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "Unknown interface cmd", false);
            return 0;
        }
    }
    return 0;
}

CommandListener::ListTtysCmd::ListTtysCmd() :
                 NetdCommand("list_ttys") {
}

int CommandListener::ListTtysCmd::runCommand(SocketClient *cli,
                                             int argc, char **argv) {
    TtyCollection *tlist = sPppCtrl->getTtyList();
    TtyCollection::iterator it;

    for (it = tlist->begin(); it != tlist->end(); ++it) {
        cli->sendMsg(ResponseCode::TtyListResult, *it, false);
    }

    cli->sendMsg(ResponseCode::CommandOkay, "Ttys listed.", false);
    return 0;
}

CommandListener::IpFwdCmd::IpFwdCmd() :
                 NetdCommand("ipfwd") {
}

int CommandListener::IpFwdCmd::runCommand(SocketClient *cli,
                                                      int argc, char **argv) {
    int rc = 0;

    if (argc < 2) {
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Missing argument", false);
        return 0;
    }

    if (!strcmp(argv[1], "status")) {
        char *tmp = NULL;

        asprintf(&tmp, "Forwarding %s", (sTetherCtrl->getIpFwdEnabled() ? "enabled" : "disabled"));
        cli->sendMsg(ResponseCode::IpFwdStatusResult, tmp, false);
        free(tmp);
        return 0;
    } else if (!strcmp(argv[1], "enable")) {
        rc = sTetherCtrl->setIpFwdEnabled(true);
    } else if (!strcmp(argv[1], "disable")) {
        rc = sTetherCtrl->setIpFwdEnabled(false);
    } else {
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Unknown ipfwd cmd", false);
        return 0;
    }

    if (!rc) {
        cli->sendMsg(ResponseCode::CommandOkay, "ipfwd operation succeeded", false);
    } else {
        cli->sendMsg(ResponseCode::OperationFailed, "ipfwd operation failed", true);
    }

    return 0;
}

CommandListener::TetherCmd::TetherCmd() :
                 NetdCommand("tether") {
}

int CommandListener::TetherCmd::runCommand(SocketClient *cli,
                                                      int argc, char **argv) {
    int rc = 0;

    if (argc < 2) {
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Missing argument", false);
        return 0;
    }

    if (!strcmp(argv[1], "stop")) {
        rc = sTetherCtrl->stopTethering();
    } else if (!strcmp(argv[1], "status")) {
        char *tmp = NULL;

        asprintf(&tmp, "Tethering services %s",
                 (sTetherCtrl->isTetheringStarted() ? "started" : "stopped"));
        cli->sendMsg(ResponseCode::TetherStatusResult, tmp, false);
        free(tmp);
        return 0;
    } else {
        /*
         * These commands take a minimum of 4 arguments
         */
        if (argc < 4) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "Missing argument", false);
            return 0;
        }

        if (!strcmp(argv[1], "start")) {
            if (argc % 2 == 1) {
                cli->sendMsg(ResponseCode::CommandSyntaxError, "Bad number of arguments", false);
                return 0;
            }

            int num_addrs = argc - 2;
            int arg_index = 2;
            int array_index = 0;
            in_addr *addrs = (in_addr *)malloc(sizeof(in_addr) * num_addrs);
            while (array_index < num_addrs) {
                if (!inet_aton(argv[arg_index++], &(addrs[array_index++]))) {
                    cli->sendMsg(ResponseCode::CommandParameterError, "Invalid address", false);
                    free(addrs);
                    return 0;
                }
            }
            rc = sTetherCtrl->startTethering(num_addrs, addrs);
            free(addrs);
        } else if (!strcmp(argv[1], "interface")) {
            if (!strcmp(argv[2], "add")) {
                rc = sTetherCtrl->tetherInterface(argv[3]);
            } else if (!strcmp(argv[2], "remove")) {
                rc = sTetherCtrl->untetherInterface(argv[3]);
            } else if (!strcmp(argv[2], "list")) {
                InterfaceCollection *ilist = sTetherCtrl->getTetheredInterfaceList();
                InterfaceCollection::iterator it;

                for (it = ilist->begin(); it != ilist->end(); ++it) {
                    cli->sendMsg(ResponseCode::TetherInterfaceListResult, *it, false);
                }
            } else {
                cli->sendMsg(ResponseCode::CommandParameterError,
                             "Unknown tether interface operation", false);
                return 0;
            }
        } else if (!strcmp(argv[1], "dns")) {
            if (!strcmp(argv[2], "set")) {
                rc = sTetherCtrl->setDnsForwarders(&argv[3], argc - 3);
            } else if (!strcmp(argv[2], "list")) {
                NetAddressCollection *dlist = sTetherCtrl->getDnsForwarders();
                NetAddressCollection::iterator it;

                for (it = dlist->begin(); it != dlist->end(); ++it) {
                    cli->sendMsg(ResponseCode::TetherDnsFwdTgtListResult, inet_ntoa(*it), false);
                }
            } else {
                cli->sendMsg(ResponseCode::CommandParameterError,
                             "Unknown tether interface operation", false);
                return 0;
            }
        } else {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "Unknown tether cmd", false);
            return 0;
        }
    }

    if (!rc) {
        cli->sendMsg(ResponseCode::CommandOkay, "Tether operation succeeded", false);
    } else {
        cli->sendMsg(ResponseCode::OperationFailed, "Tether operation failed", true);
    }

    return 0;
}

CommandListener::NatCmd::NatCmd() :
                 NetdCommand("nat") {
}

int CommandListener::NatCmd::runCommand(SocketClient *cli,
                                                      int argc, char **argv) {
    int rc = 0;

    if (argc < 3) {
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Missing argument", false);
        return 0;
    }

    if (!strcmp(argv[1], "enable")) {
        rc = sNatCtrl->enableNat(argv[2], argv[3]);
    } else if (!strcmp(argv[1], "disable")) {
        rc = sNatCtrl->disableNat(argv[2], argv[3]);
    } else {
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Unknown nat cmd", false);
        return 0;
    }

    if (!rc) {
        cli->sendMsg(ResponseCode::CommandOkay, "Nat operation succeeded", false);
    } else {
        cli->sendMsg(ResponseCode::OperationFailed, "Nat operation failed", true);
    }

    return 0;
}

CommandListener::PppdCmd::PppdCmd() :
                 NetdCommand("pppd") {
}

int CommandListener::PppdCmd::runCommand(SocketClient *cli,
                                                      int argc, char **argv) {
    int rc = 0;

    if (argc < 3) {
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Missing argument", false);
        return 0;
    }

    if (!strcmp(argv[1], "attach")) {
        struct in_addr l, r, dns1, dns2;

        memset(&dns1, sizeof(struct in_addr), 0);
        memset(&dns2, sizeof(struct in_addr), 0);

        if (!inet_aton(argv[3], &l)) {
            cli->sendMsg(ResponseCode::CommandParameterError, "Invalid local address", false);
            return 0;
        }
        if (!inet_aton(argv[4], &r)) {
            cli->sendMsg(ResponseCode::CommandParameterError, "Invalid remote address", false);
            return 0;
        }
        if ((argc > 3) && (!inet_aton(argv[5], &dns1))) {
            cli->sendMsg(ResponseCode::CommandParameterError, "Invalid dns1 address", false);
            return 0;
        }
        if ((argc > 4) && (!inet_aton(argv[6], &dns2))) {
            cli->sendMsg(ResponseCode::CommandParameterError, "Invalid dns2 address", false);
            return 0;
        }
        rc = sPppCtrl->attachPppd(argv[2], l, r, dns1, dns2);
    } else if (!strcmp(argv[1], "detach")) {
        rc = sPppCtrl->detachPppd(argv[2]);
    } else {
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Unknown pppd cmd", false);
        return 0;
    }

    if (!rc) {
        cli->sendMsg(ResponseCode::CommandOkay, "Pppd operation succeeded", false);
    } else {
        cli->sendMsg(ResponseCode::OperationFailed, "Pppd operation failed", true);
    }

    return 0;
}

CommandListener::PanCmd::PanCmd() :
                 NetdCommand("pan") {
}

int CommandListener::PanCmd::runCommand(SocketClient *cli,
                                        int argc, char **argv) {
    int rc = 0;

    if (argc < 2) {
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Missing argument", false);
        return 0;
    }

    if (!strcmp(argv[1], "start")) {
        rc = sPanCtrl->startPan();
    } else if (!strcmp(argv[1], "stop")) {
        rc = sPanCtrl->stopPan();
    } else if (!strcmp(argv[1], "status")) {
        char *tmp = NULL;

        asprintf(&tmp, "Pan services %s",
                 (sPanCtrl->isPanStarted() ? "started" : "stopped"));
        cli->sendMsg(ResponseCode::PanStatusResult, tmp, false);
        free(tmp);
        return 0;
    } else {
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Unknown pan cmd", false);
        return 0;
    }

    if (!rc) {
        cli->sendMsg(ResponseCode::CommandOkay, "Pan operation succeeded", false);
    } else {
        cli->sendMsg(ResponseCode::OperationFailed, "Pan operation failed", true);
    }

    return 0;
}

CommandListener::SoftapCmd::SoftapCmd() :
                 NetdCommand("softap") {
}

int CommandListener::SoftapCmd::runCommand(SocketClient *cli,
                                        int argc, char **argv) {
    int rc = 0, flag = 0;

    if (argc < 2) {
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Softap Missing argument", false);
        return 0;
    }

    if (!strcmp(argv[1], "start")) {
        rc = sSoftapCtrl->startDriver(argv[2]);
    } else if (!strcmp(argv[1], "stop")) {
        rc = sSoftapCtrl->stopDriver(argv[2]);
    } else if (!strcmp(argv[1], "startap")) {
        rc = sSoftapCtrl->startSoftap();
    } else if (!strcmp(argv[1], "stopap")) {
        rc = sSoftapCtrl->stopSoftap();
    } else if (!strcmp(argv[1], "fwreload")) {
        rc = sSoftapCtrl->fwReloadSoftap(argc, argv);
    } else if (!strcmp(argv[1], "status")) {
        char *tmp = NULL;

        asprintf(&tmp, "Softap service %s",
                 (sSoftapCtrl->isSoftapStarted() ? "started" : "stopped"));
        cli->sendMsg(ResponseCode::SoftapStatusResult, tmp, false);
        free(tmp);
        return 0;
    } else if (!strcmp(argv[1], "set")) {
        rc = sSoftapCtrl->setSoftap(argc, argv);
    } else {
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Softap Unknown cmd", false);
        return 0;
    }

    if (!rc) {
        cli->sendMsg(ResponseCode::CommandOkay, "Softap operation succeeded", false);
    } else {
        cli->sendMsg(ResponseCode::OperationFailed, "Softap operation failed", true);
    }

    return 0;
}

CommandListener::UsbCmd::UsbCmd() :
                 NetdCommand("usb") {
}

int CommandListener::UsbCmd::runCommand(SocketClient *cli, int argc, char **argv) {
    int rc = 0;

    if (argc < 2) {
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Usb Missing argument", false);
        return 0;
    }

    if (!strcmp(argv[1], "startrndis")) {
        rc = sUsbCtrl->startRNDIS();
    } else if (!strcmp(argv[1], "stoprndis")) {
        rc = sUsbCtrl->stopRNDIS();
    } else if (!strcmp(argv[1], "rndisstatus")) {
        char *tmp = NULL;

        asprintf(&tmp, "Usb RNDIS %s",
                (sUsbCtrl->isRNDISStarted() ? "started" : "stopped"));
        cli->sendMsg(ResponseCode::UsbRNDISStatusResult, tmp, false);
        free(tmp);
        return 0;
    } else {
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Usb Unknown cmd", false);
        return 0;
    }

    if (!rc) {
        cli->sendMsg(ResponseCode::CommandOkay, "Usb operation succeeded", false);
    } else {
        cli->sendMsg(ResponseCode::OperationFailed, "Softap operation failed", true);
    }

    return 0;
}

CommandListener::ResolverCmd::ResolverCmd() :
        NetdCommand("resolver") {
}

int CommandListener::ResolverCmd::runCommand(SocketClient *cli, int argc, char **argv) {
    int rc = 0;
    struct in_addr addr;

    if (argc < 2) {
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Resolver missing arguments", false);
        return 0;
    }

    if (!strcmp(argv[1], "setdefaultif")) { // "resolver setdefaultif <iface>"
        if (argc == 3) {
            rc = sResolverCtrl->setDefaultInterface(argv[2]);
        } else {
            cli->sendMsg(ResponseCode::CommandSyntaxError,
                    "Wrong number of arguments to resolver setdefaultif", false);
            return 0;
        }
    } else if (!strcmp(argv[1], "setifdns")) { // "resolver setifdns <iface> <dns1> <dns2> ..."
        if (argc >= 4) {
            rc = sResolverCtrl->setInterfaceDnsServers(argv[2], &argv[3], argc - 3);
        } else {
            cli->sendMsg(ResponseCode::CommandSyntaxError,
                    "Wrong number of arguments to resolver setifdns", false);
            return 0;
        }

        // set the address of the interface to which the name servers
        // are bound. Required in order to bind to right interface when
        // doing the dns query.
        if (!rc) {
            ifc_init();
            ifc_get_info(argv[2], &addr.s_addr, NULL, 0);

            rc = sResolverCtrl->setInterfaceAddress(argv[2], &addr);
        }
    } else if (!strcmp(argv[1], "flushdefaultif")) { // "resolver flushdefaultif"
        if (argc == 2) {
            rc = sResolverCtrl->flushDefaultDnsCache();
        } else {
            cli->sendMsg(ResponseCode::CommandSyntaxError,
                    "Wrong number of arguments to resolver flushdefaultif", false);
            return 0;
        }
    } else if (!strcmp(argv[1], "flushif")) { // "resolver flushif <iface>"
        if (argc == 3) {
            rc = sResolverCtrl->flushInterfaceDnsCache(argv[2]);
        } else {
            cli->sendMsg(ResponseCode::CommandSyntaxError,
                    "Wrong number of arguments to resolver setdefaultif", false);
            return 0;
        }
    } else {
        cli->sendMsg(ResponseCode::CommandSyntaxError,"Resolver unknown command", false);
        return 0;
    }

    if (!rc) {
        cli->sendMsg(ResponseCode::CommandOkay, "Resolver command succeeded", false);
    } else {
        cli->sendMsg(ResponseCode::OperationFailed, "Resolver command failed", true);
    }

    return 0;
}

int CommandListener::readInterfaceCounters(const char *iface, unsigned long *rx, unsigned long *tx) {
    FILE *fp = fopen("/proc/net/dev", "r");
    if (!fp) {
        LOGE("Failed to open /proc/net/dev (%s)", strerror(errno));
        return -1;
    }

    char buffer[512];

    fgets(buffer, sizeof(buffer), fp); // Header 1
    fgets(buffer, sizeof(buffer), fp); // Header 2
    while(fgets(buffer, sizeof(buffer), fp)) {
        buffer[strlen(buffer)-1] = '\0';

        char name[31];
        unsigned long d;
        sscanf(buffer, "%30s %lu %lu %lu %lu %lu %lu %lu %lu %lu",
                name, rx, &d, &d, &d, &d, &d, &d, &d, tx);
        char *rxString = strchr(name, ':');
        *rxString = '\0';
        rxString++;
        // when the rx count gets too big it changes from "name: 999" to "name:1000"
        // and the sscanf munge the two together.  Detect that and fix
        // note that all the %lu will be off by one and the real tx value will be in d
        if (*rxString != '\0') {
            *tx = d;
            sscanf(rxString, "%20lu", rx);
        }
        if (strcmp(name, iface)) {
            continue;
        }
        fclose(fp);
        return 0;
    }

    fclose(fp);
    *rx = 0;
    *tx = 0;
    return 0;
}
