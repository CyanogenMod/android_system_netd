/*
 * Copyright (C) 2014 The Android Open Source Project
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

#include "Fwmark.h"

namespace {

const uint32_t FWMARK_MASK_NET_ID = 0xffff;
const uint32_t FWMARK_MASK_EXPLICIT = 0x10000;
const uint32_t FWMARK_MASK_PROTECT = 0x20000;
const uint32_t FWMARK_MASK_CHANGE_NETWORK_STATE = 0x40000;
const uint32_t FWMARK_MASK_CONNECTIVITY_INTERNAL = 0x80000;

}  // namespace

uint32_t getFwmark(unsigned netId, bool exp, bool protect, Permission permission) {
    uint32_t fwmark = netId & FWMARK_MASK_NET_ID;
    if (exp) {
        fwmark |= FWMARK_MASK_EXPLICIT;
    }
    if (protect) {
        fwmark |= FWMARK_MASK_PROTECT;
    }
    if (permission & PERMISSION_CHANGE_NETWORK_STATE) {
        fwmark |= FWMARK_MASK_CHANGE_NETWORK_STATE;
    }
    if (permission & PERMISSION_CONNECTIVITY_INTERNAL) {
        fwmark |= FWMARK_MASK_CONNECTIVITY_INTERNAL;
    }
    return fwmark;
}

uint32_t getFwmarkMask(bool netId, bool exp, bool protect, Permission permission) {
    return getFwmark(netId ? FWMARK_MASK_NET_ID : 0, exp, protect, permission);
}
