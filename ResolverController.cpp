/*
 * Copyright (C) 2011 The Android Open Source Project
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

#define LOG_TAG "ResolverController"
#define DBG 0

#include <cutils/log.h>

#include <linux/if.h>
#include <resolv.h>

#include "ResolverController.h"

int ResolverController::setDefaultInterface(const char* iface) {
    if (DBG) {
        LOGD("setDefaultInterface iface = %s\n", iface);
    }

    _resolv_set_default_iface(iface);

    return 0;
}

int ResolverController::setInterfaceDnsServers(const char* iface, char** servers, int numservers) {
    if (DBG) {
        LOGD("setInterfaceDnsServers iface = %s\n", iface);
    }

    _resolv_set_nameservers_for_iface(iface, servers, numservers);

    return 0;
}

int ResolverController::setInterfaceAddress(const char* iface, struct in_addr* addr) {
    if (DBG) {
        LOGD("setInterfaceAddress iface = %s\n", iface);
    }

    _resolv_set_addr_of_iface(iface, addr);

    return 0;
}

int ResolverController::flushDefaultDnsCache() {
    if (DBG) {
        LOGD("flushDefaultDnsCache\n");
    }

    _resolv_flush_cache_for_default_iface();

    return 0;
}

int ResolverController::flushInterfaceDnsCache(const char* iface) {
    if (DBG) {
        LOGD("flushInterfaceDnsCache iface = %s\n", iface);
    }

    _resolv_flush_cache_for_iface(iface);

    return 0;
}
