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

#ifndef _FWMARK_H
#define _FWMARK_H

const unsigned int FWMARK_NETID = 0xffff;
const unsigned int FWMARK_EXPLICIT = 0x10000;
const unsigned int FWMARK_PROTECT = 0x20000;
const unsigned int FWMARK_CNS = 0x40000;  // CHANGE_NETWORK_STATE
const unsigned int FWMARK_CI = 0x80000;  // CONNECTIVITY_INTERNAL

unsigned int getFwmark(unsigned int netId, bool exp, bool protect, bool cns,
                       bool ci) {
    unsigned int fwmark = netId & FWMARK_NETID;
    if (exp) fwmark |= FWMARK_EXPLICIT;
    if (protect) fwmark |= FWMARK_PROTECT;
    if (cns) fwmark |= FWMARK_CNS;
    if (ci) fwmark |= FWMARK_CI;
    return fwmark;
}

unsigned int getFwmarkMask(bool netId, bool exp, bool protect, bool cns, bool ci) {
    return getFwmark(netId ? FWMARK_NETID : 0, exp, protect, cns, ci);
}
#endif
