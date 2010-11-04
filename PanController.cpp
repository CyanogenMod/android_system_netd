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

#ifdef HAVE_BLUETOOTH
#include <bluedroid/bluetooth.h>
#endif

#define LOG_TAG "PanController"
#include <cutils/log.h>

#include "PanController.h"

#ifdef HAVE_BLUETOOTH
extern "C" int bt_is_enabled();
#endif

PanController::PanController() {
    mPid = 0;
}

PanController::~PanController() {
}

int PanController::startPan() {
    pid_t pid;

#ifdef HAVE_BLUETOOTH
    if (!bt_is_enabled()) {
        LOGE("Cannot start PAN services - Bluetooth not running");
        errno = ENODEV;
        return -1;
    }
#else
    LOGE("Cannot start PAN services - No Bluetooth support");
    errno = ENODEV;
    return -1;
#endif

    if (mPid) {
        LOGE("PAN already started");
        errno = EBUSY;
        return -1;
    }

   if ((pid = fork()) < 0) {
        LOGE("fork failed (%s)", strerror(errno));
        return -1;
    }

    if (!pid) {
        if (execl("/system/bin/pand", "/system/bin/pand", "--nodetach", "--listen",
                  "--role", "NAP", (char *) NULL)) {
            LOGE("execl failed (%s)", strerror(errno));
        }
        LOGE("Should never get here!");
        return 0;
    } else {
        mPid = pid;
    }
    return 0;

}

int PanController::stopPan() {
    if (mPid == 0) {
        LOGE("PAN already stopped");
        return 0;
    }

    LOGD("Stopping PAN services");
    kill(mPid, SIGTERM);
    waitpid(mPid, NULL, 0);
    mPid = 0;
    LOGD("PAN services stopped");
    return 0;
}

bool PanController::isPanStarted() {
    return (mPid != 0 ? true : false);
}
