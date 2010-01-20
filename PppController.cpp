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
#include <errno.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define LOG_TAG "PppController"
#include <cutils/log.h>

#include "PppController.h"

extern "C" int logwrap(int argc, const char **argv, int background);

static char IPTABLES_PATH[] = "/system/bin/iptables";

PppController::PppController() {
    mTtys = new TtyCollection();
    mPid = 0;
}

PppController::~PppController() {
    TtyCollection::iterator it;

    for (it = mTtys->begin(); it != mTtys->end(); ++it) {
        free(*it);
    }
    mTtys->clear();
}

int PppController::attachPppd(const char *tty, struct in_addr local,
                              struct in_addr remote) {
    pid_t pid;

    if (mPid) {
        LOGE("Multiple PPPD instances not currently supported");
        errno = EBUSY;
        return -1;
    }

    if ((pid = fork()) < 0) {
        LOGE("fork failed (%s)", strerror(errno));
        return -1;
    }

    if (!pid) {
        char *l = strdup(inet_ntoa(local));
        char *r = strdup(inet_ntoa(remote));
        char dev[32];
        char *lr;

        asprintf(&lr, "%s:%s", l, r);

        snprintf(dev, sizeof(dev), "/dev/%s", tty); // TODO: STOPSHIP Validate this

        // TODO: Deal with pppd bailing out after 99999 seconds of being started
        // but not getting a connection
        if (execl("/system/bin/pppd", "/system/bin/pppd", "-detach", dev,
                  "115200", lr, "debug", "lcp-max-configure", "99999", (char *) NULL)) {
            LOGE("execl failed (%s)", strerror(errno));
        }
        LOGE("Should never get here!");
        return 0;
    } else {
        mPid = pid;
    }
    return 0;
}

int PppController::detachPppd(const char *tty) {

    if (mPid == 0) {
        LOGE("PPPD already stopped");
        return 0;
    }

    LOGD("Stopping PPPD services on port %s", tty);

    kill(mPid, SIGTERM);
    mPid = 0;
    return 0;
}

TtyCollection *PppController::getTtyList() {
    return mTtys;
}

