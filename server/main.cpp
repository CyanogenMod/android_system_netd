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

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <dirent.h>

#define LOG_TAG "Netd"

#include "cutils/log.h"

#include "CommandListener.h"
#include "NetlinkManager.h"
#include "DnsProxyListener.h"
#include "MDnsSdListener.h"
#include "FwmarkServer.h"

static void blockSigpipe();

int main() {

    CommandListener *cl;
    NetlinkManager *nm;
    DnsProxyListener *dpl;
    MDnsSdListener *mdnsl;
    FwmarkServer* fwmarkServer;

    ALOGI("Netd 1.0 starting");

    blockSigpipe();

    if (!(nm = NetlinkManager::Instance())) {
        ALOGE("Unable to create NetlinkManager");
        exit(1);
    };

    cl = new CommandListener();
    nm->setBroadcaster((SocketListener *) cl);

    if (nm->start()) {
        ALOGE("Unable to start NetlinkManager (%s)", strerror(errno));
        exit(1);
    }

    // Set local DNS mode, to prevent bionic from proxying
    // back to this service, recursively.
    setenv("ANDROID_DNS_MODE", "local", 1);
    dpl = new DnsProxyListener(CommandListener::sNetCtrl);
    if (dpl->startListener()) {
        ALOGE("Unable to start DnsProxyListener (%s)", strerror(errno));
        exit(1);
    }

    mdnsl = new MDnsSdListener();
    if (mdnsl->startListener()) {
        ALOGE("Unable to start MDnsSdListener (%s)", strerror(errno));
        exit(1);
    }

    fwmarkServer = new FwmarkServer(CommandListener::sNetCtrl);
    if (fwmarkServer->startListener()) {
        ALOGE("Unable to start FwmarkServer (%s)", strerror(errno));
        exit(1);
    }

    /*
     * Now that we're up, we can respond to commands
     */
    if (cl->startListener()) {
        ALOGE("Unable to start CommandListener (%s)", strerror(errno));
        exit(1);
    }

    // Eventually we'll become the monitoring thread
    while(1) {
        sleep(1000);
    }

    ALOGI("Netd exiting");
    exit(0);
}

static void blockSigpipe()
{
    sigset_t mask;

    sigemptyset(&mask);
    sigaddset(&mask, SIGPIPE);
    if (sigprocmask(SIG_BLOCK, &mask, NULL) != 0)
        ALOGW("WARNING: SIGPIPE not blocked\n");
}
