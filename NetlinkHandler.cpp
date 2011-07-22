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
#include <string.h>
#include <errno.h>

#define LOG_TAG "Netd"

#include <cutils/log.h>

#include <sysutils/NetlinkEvent.h>
#include "NetlinkHandler.h"
#include "NetlinkManager.h"
#include "ResponseCode.h"

NetlinkHandler::NetlinkHandler(NetlinkManager *nm, int listenerSocket,
                               int format) :
                        NetlinkListener(listenerSocket, format) {
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
        const char *iface = evt->findParam("INTERFACE");

        if (action == evt->NlActionAdd) {
            notifyInterfaceAdded(iface);
        } else if (action == evt->NlActionRemove) {
            notifyInterfaceRemoved(iface);
        } else if (action == evt->NlActionChange) {
            evt->dump();
            notifyInterfaceChanged("nana", true);
        } else if (action == evt->NlActionLinkUp) {
            notifyInterfaceLinkChanged(iface, true);
        } else if (action == evt->NlActionLinkDown) {
            notifyInterfaceLinkChanged(iface, false);
        }
    } else if (!strcmp(subsys, "qlog")) {
        const char *alertName = evt->findParam("ALERT_NAME");
        const char *iface = evt->findParam("INTERFACE");
        notifyQuotaLimitReached(alertName, iface);
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
    snprintf(msg, sizeof(msg), "Iface changed %s %s", name,
             (isUp ? "up" : "down"));

    mNm->getBroadcaster()->sendBroadcast(ResponseCode::InterfaceChange,
            msg, false);
}

void NetlinkHandler::notifyInterfaceLinkChanged(const char *name, bool isUp) {
    char msg[255];
    snprintf(msg, sizeof(msg), "Iface linkstate %s %s", name,
             (isUp ? "up" : "down"));

    mNm->getBroadcaster()->sendBroadcast(ResponseCode::InterfaceChange,
            msg, false);
}

void NetlinkHandler::notifyQuotaLimitReached(const char *name, const char *iface) {
    char msg[255];
    snprintf(msg, sizeof(msg), "limit alert %s %s", name, iface);

    mNm->getBroadcaster()->sendBroadcast(ResponseCode::BandwidthControl,
            msg, false);
}
