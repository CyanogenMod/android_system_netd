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
#include <fcntl.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#define LOG_TAG "SoftapController"
#include <cutils/log.h>

#include "SoftapController.h"

SoftapController::SoftapController() {
    mPid = 0;
}

SoftapController::~SoftapController() {
}

int SoftapController::startSoftap() {
    pid_t pid = 1;

    LOGD("Softap start");
    if (mPid) {
        LOGE("Softap already started");
        errno = EBUSY;
        return -1;
    }
#if 0
   if ((pid = fork()) < 0) {
        LOGE("fork failed (%s)", strerror(errno));
        return -1;
    }
#endif
    if (!pid) {
        LOGE("Softap Started");
        return 0;
    } else {
        mPid = pid;
    }
    return 0;

}

int SoftapController::stopSoftap() {
    LOGD("Softap stop");
    if (mPid == 0) {
        LOGE("Softap already stopped");
        return 0;
    }
#if 0
    LOGD("Stopping Softap service");
    kill(mPid, SIGTERM);
    waitpid(mPid, NULL, 0);
#endif
    mPid = 0;
    LOGD("Softap service stopped");
    return 0;
}

bool SoftapController::isSoftapStarted() {
    return (mPid != 0 ? true : false);
}

int SoftapController::setSoftap(int argc, char *argv[]) {
    LOGD("Softap set");
    return 0;
}
