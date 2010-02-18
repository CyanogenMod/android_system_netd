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
#include <errno.h>

#define LOG_TAG "Netd"

#include <cutils/log.h>

#include <sysutils/NetlinkEvent.h>
#include "NetlinkHandler.h"
#include "NetlinkManager.h"
#include "ResponseCode.h"

NetlinkHandler::NetlinkHandler(NetlinkManager *nm, int listenerSocket) :
                NetlinkListener(listenerSocket) {
    mNm = nm;
}

NetlinkHandler::~NetlinkHandler() {
}

int NetlinkHandler::start() {
    return this->startListener();
}

int NetlinkHandler::stop() {
    return this->stopListener();
}

void NetlinkHandler::onEvent(NetlinkEvent *evt) {
    const char *subsys = evt->getSubsystem();
    if (!subsys) {
        LOGW("No subsystem found in netlink event");
        return;
    }
    if (!strcmp(subsys, "net")) {
        int action = evt->getAction();
        if (action == evt->NlActionAdd) {
            const char *iface = evt->findParam("INTERFACE");
            notifyInterfaceAdded(iface);
        } else if (action == evt->NlActionRemove) {
            const char *iface = evt->findParam("INTERFACE");
            notifyInterfaceRemoved(iface);
        } else if (action == evt->NlActionChange) {
            evt->dump();
            const char *iface = evt->findParam("INTERFACE");
            notifyInterfaceChanged("nana", true);
        }
    }
}

void NetlinkHandler::notifyInterfaceAdded(const char *name) {
    char msg[255];
    snprintf(msg, sizeof(msg), "Iface added %s", name);

    mNm->getBroadcaster()->sendBroadcast(ResponseCode::InterfaceChange,
            msg, false);
}

void NetlinkHandler::notifyInterfaceRemoved(const char *name) {
    char msg[255];
    snprintf(msg, sizeof(msg), "Iface removed %s", name);

    mNm->getBroadcaster()->sendBroadcast(ResponseCode::InterfaceChange,
            msg, false);
}

void NetlinkHandler::notifyInterfaceChanged(const char *name, bool isUp) {
    char msg[255];
    snprintf(msg, sizeof(msg), "Iface is %s %s", (isUp ? "up" : "down"), name);

    mNm->getBroadcaster()->sendBroadcast(ResponseCode::InterfaceChange,
            msg, false);
}
