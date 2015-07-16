/*
   Copyright (c) 2015, The Linux Foundation. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above
      copyright notice, this list of conditions and the following
      disclaimer in the documentation and/or other materials provided
      with the distribution.
    * Neither the name of The Linux Foundation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
*/

#ifndef _QTI_CONNECTIVITY_CONTROLLER_H
#define _QTI_CONNECTIVITY_CONTROLLER_H

#include <string>

#include "NetdCommand.h"

class QtiConnectivityController {
public:
    QtiConnectivityController();
    ~QtiConnectivityController();
    NetdCommand *getQtiConnectivityCmd();
    void natStarted(const char* tetherIface, const char* upstreamIface);
    void natStopped(const char* tetherIface, const char* upstreamIface);

private:
    static const int INTENT_COMMAND_MAX_SIZE = 2056;
    static const char* INTENT_COMMAND;
    static const char* INTENT_STRING_EXTRA_OPT;
    static const char* INTENT_TETHER_IFACE_EXTRA_KEY;
    static const char* INTENT_UPSTREAM_IFACE_EXTRA_KEY;
    static const char* INTENT_INCLUDE_STOPPED_PACKAGES;

    class QtiTetherCommand : NetdCommand {
    public:
        QtiTetherCommand();
        virtual ~QtiTetherCommand();
        int runCommand(SocketClient* client, int argc, char** argv);
        NetdCommand *asNetdCommand();

    private:
        static const char* IF_INDEX_PATH;
        static const int PROC_PATH_SIZE = 255;
        static const int SYS_PATH_SIZE = PROC_PATH_SIZE;

        static const char* IP6_CFG_ALL_PROXY_NDP;
        static const char* IP6_CFG_ALL_FORWARDING;

        static const int TETHER_ARGS_LEN = 2;
        static const int TETHER_IFACE_MAX_LEN = 256;

        static const char* RTRADVDAEMON;
        static const int RTRADVDAEMON_ARGS_COUNT = TETHER_ARGS_LEN * 2 + 5;
        static const int RTRADVDAEMON_ARGS_MAX_LEN = TETHER_IFACE_MAX_LEN;

        static const int MAX_TABLE_LEN = 11;
        static const int MIN_TABLE_NUMBER = 0;
        static const int BASE_TABLE_NUMBER = 1000;

        int startTethering(const char* tetherIface, const char* upstreamIface);
        int stopTethering();
        bool isRtrAdvStarted();
        int startRtrAdv(char* tetherIface, char* upstreamIface, int table_number);
        int stopRtrAdv();
        static int getIfaceIndexForIface(const char *iface);
        static int configWriteSetting(const char *path, const char *value);
        static int setIpFwdEnabled(bool enable);

        int mRtrAdvPid;
    };

    QtiTetherCommand *mTetherCmd;
    QtiTetherCommand *getQtiTetherCommand();
};

#endif
