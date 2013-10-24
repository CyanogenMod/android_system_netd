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

#include <stdarg.h>
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
        ALOGW("No subsystem found in netlink event");
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
        } else if (action == evt->NlActionAddressUpdated ||
                   action == evt->NlActionAddressRemoved) {
            const char *address = evt->findParam("ADDRESS");
            const char *flags = evt->findParam("FLAGS");
            const char *scope = evt->findParam("SCOPE");
            if (iface && flags && scope) {
                notifyAddressChanged(action, address, iface, flags, scope);
            }
        } else if (action == evt->NlActionRdnss) {
            const char *lifetime = evt->findParam("LIFETIME");
            const char *servers = evt->findParam("SERVERS");
            if (lifetime && servers) {
                notifyInterfaceDnsServers(iface, lifetime, servers);
            }
        }

    } else if (!strcmp(subsys, "qlog")) {
        const char *alertName = evt->findParam("ALERT_NAME");
        const char *iface = evt->findParam("INTERFACE");
        notifyQuotaLimitReached(alertName, iface);

    } else if (!strcmp(subsys, "xt_idletimer")) {
        int action = evt->getAction();
        const char *label = evt->findParam("LABEL");
        const char *state = evt->findParam("STATE");
        // if no LABEL, use INTERFACE instead
        if (label == NULL) {
            label = evt->findParam("INTERFACE");
        }
        if (state)
            notifyInterfaceClassActivity(label, !strcmp("active", state));

#if !LOG_NDEBUG
    } else if (strcmp(subsys, "platform") && strcmp(subsys, "backlight")) {
        /* It is not a VSYNC or a backlight event */
        ALOGV("unexpected event from subsystem %s", subsys);
#endif
    }
}

void NetlinkHandler::notify(int code, const char *format, ...) {
    char *msg;
    va_list args;
    va_start(args, format);
    if (vasprintf(&msg, format, args) >= 0) {
        mNm->getBroadcaster()->sendBroadcast(code, msg, false);
        free(msg);
    } else {
        SLOGE("Failed to send notification: vasprintf: %s", strerror(errno));
    }
    va_end(args);
}

void NetlinkHandler::notifyInterfaceAdded(const char *name) {
    notify(ResponseCode::InterfaceChange, "Iface added %s", name);
}

void NetlinkHandler::notifyInterfaceRemoved(const char *name) {
    notify(ResponseCode::InterfaceChange, "Iface removed %s", name);
}

void NetlinkHandler::notifyInterfaceChanged(const char *name, bool isUp) {
    notify(ResponseCode::InterfaceChange,
           "Iface changed %s %s", name, (isUp ? "up" : "down"));
}

void NetlinkHandler::notifyInterfaceLinkChanged(const char *name, bool isUp) {
    notify(ResponseCode::InterfaceChange,
           "Iface linkstate %s %s", name, (isUp ? "up" : "down"));
}

void NetlinkHandler::notifyQuotaLimitReached(const char *name, const char *iface) {
    notify(ResponseCode::BandwidthControl, "limit alert %s %s", name, iface);
}

void NetlinkHandler::notifyInterfaceClassActivity(const char *name,
                                                  bool isActive) {
    notify(ResponseCode::InterfaceClassActivity,
           "IfaceClass %s %s", isActive ? "active" : "idle", name);
}

void NetlinkHandler::notifyAddressChanged(int action, const char *addr,
                                          const char *iface, const char *flags,
                                          const char *scope) {
    notify(ResponseCode::InterfaceAddressChange,
           "Address %s %s %s %s %s",
           (action == NetlinkEvent::NlActionAddressUpdated) ?
           "updated" : "removed", addr, iface, flags, scope);
}

void NetlinkHandler::notifyInterfaceDnsServers(const char *iface,
                                               const char *lifetime,
                                               const char *servers) {
    notify(ResponseCode::InterfaceDnsInfo, "DnsInfo servers %s %s %s",
           iface, lifetime, servers);
}
