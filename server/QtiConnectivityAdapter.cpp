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

#define LOG_NDEBUG 0
#define LOG_TAG "QtiConnectivityAdapter"

#include <cutils/log.h>
#include <dlfcn.h>
#include <sysutils/SocketClient.h>
#include <sysutils/SocketListener.h>

#include "CommandListener.h"
#include "NetdCommand.h"
#include "QtiConnectivityAdapter.h"
#include "ResponseCode.h"

void *_libConnectivityHandle = NULL;
void (*_initExtension) (SocketListener*) = NULL;
int (*_runQtiConnectivityCmd) (SocketClient*, int, char**) = NULL;
void (*_natStarted) (const char*, const char*) = NULL;
void (*_natStopped) (const char*, const char*) = NULL;
int (*_getV6TetherStats) (SocketClient*, const char*, const char*, std::string&) = NULL;

void initLibrary() {
    if (!_libConnectivityHandle) {
        _libConnectivityHandle = dlopen("libconnctrl.so", RTLD_NOW);
        if (_libConnectivityHandle) {
            *(void **)&_initExtension =
                    dlsym(_libConnectivityHandle, "initExtension");
            *(void **)&_runQtiConnectivityCmd =
                    dlsym(_libConnectivityHandle, "runConnectivityCmd");
            *(void **)&_natStarted =
                    dlsym(_libConnectivityHandle, "natStarted");
            *(void **)&_natStopped =
                    dlsym(_libConnectivityHandle, "natStopped");
            *(void **)&_getV6TetherStats =
                    dlsym(_libConnectivityHandle, "getV6TetherStats");
            ALOGD("Successfully loaded %s", "libconnectivitycontroller");
        } else {
            ALOGI("Failed to open libconnctrl, "
                    "some features may not be present.");
        }
    }
}

NetdCommand* getQtiConnectivityCmd(CommandListener *broadcaster) {
    initLibrary();
    if (_initExtension) _initExtension(broadcaster);
    return (new QtiConnectivityCommand)->asNetdCommand();
}

void natStarted(const char* tetherIface, const char* upstreamIface) {
    ALOGI("natStarted(tether=%s upstream=%s)", tetherIface, upstreamIface);
    if (_natStarted) _natStarted(tetherIface, upstreamIface);
}

void natStopped(const char* tetherIface, const char* upstreamIface) {
    ALOGI("natStopped(tether=%s upstream=%s)", tetherIface, upstreamIface);
    if (_natStopped) _natStopped(tetherIface, upstreamIface);
}

int getV6TetherStats
(
    SocketClient *cli,
    const char* tetherIface,
    const char* upstreamIface,
    std::string &extraProcessingInfo
) {
    ALOGI("getV6TetherStats(tether=%s upstream=%s)", tetherIface, upstreamIface);
    if (_getV6TetherStats) return _getV6TetherStats(cli,
                                                        tetherIface,
                                                        upstreamIface,
                                                        extraProcessingInfo);
    return 0;
}

NetdCommand *QtiConnectivityCommand::asNetdCommand() {
    return static_cast<NetdCommand*>(this);
}

int QtiConnectivityCommand::runCommand
(
    SocketClient *cli,
    int argc,
    char **argv
) {
    if (_runQtiConnectivityCmd) {
        return _runQtiConnectivityCmd(cli, argc, argv);
    } else {
        cli->sendMsg(ResponseCode::OperationFailed, "Extension not loaded", false);
    }
    return 0;
}
