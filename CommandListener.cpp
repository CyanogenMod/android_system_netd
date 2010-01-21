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

#define LOG_TAG "CommandListener"
#include <cutils/log.h>

#include <sysutils/SocketClient.h>

#include "CommandListener.h"
#include "ResponseCode.h"

TetherController *CommandListener::sTetherCtrl = NULL;
NatController *CommandListener::sNatCtrl = NULL;
PppController *CommandListener::sPppCtrl = NULL;
PanController *CommandListener::sPanCtrl = NULL;

CommandListener::CommandListener() :
                 FrameworkListener("netd") {
    registerCmd(new ListInterfacesCmd());
    registerCmd(new IpFwdCmd());
    registerCmd(new TetherCmd());
    registerCmd(new NatCmd());
    registerCmd(new ListTtysCmd());
    registerCmd(new PppdCmd());
    registerCmd(new PanCmd());

    if (!sTetherCtrl)
        sTetherCtrl = new TetherController();
    if (!sNatCtrl)
        sNatCtrl = new NatController();
    if (!sPppCtrl)
        sPppCtrl = new PppController();
    if (!sPanCtrl)
        sPanCtrl = new PanController();
}

CommandListener::ListInterfacesCmd::ListInterfacesCmd() :
                 NetdCommand("list_interfaces") {
}

int CommandListener::ListInterfacesCmd::runCommand(SocketClient *cli,
                                                      int argc, char **argv) {
    // XXX: Send a series of InterfaceListResults
    cli->sendMsg(ResponseCode::CommandOkay, "Interfaces listed.", false);
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
            struct in_addr s, e;

            if (!inet_aton(argv[2], &s)) {
                cli->sendMsg(ResponseCode::CommandParameterError, "Invalid start address", false);
                return 0;
            }
            if (!inet_aton(argv[3], &e)) {
                cli->sendMsg(ResponseCode::CommandParameterError, "Invalid end address", false);
                return 0;
            }
            rc = sTetherCtrl->startTethering(s, e);
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
        struct in_addr l, r;

        if (!inet_aton(argv[3], &l)) {
            cli->sendMsg(ResponseCode::CommandParameterError, "Invalid local address", false);
            return 0;
        }
        if (!inet_aton(argv[4], &r)) {
            cli->sendMsg(ResponseCode::CommandParameterError, "Invalid remote address", false);
            return 0;
        }
        rc = sPppCtrl->attachPppd(argv[2], l, r);
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
