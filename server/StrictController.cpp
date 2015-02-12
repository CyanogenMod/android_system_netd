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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "StrictController"
#define LOG_NDEBUG 0

#include <cutils/log.h>

#include "ConnmarkFlags.h"
#include "NetdConstants.h"
#include "StrictController.h"

const char* StrictController::LOCAL_OUTPUT = "st_OUTPUT";
const char* StrictController::LOCAL_CLEAR_DETECT = "st_clear_detect";
const char* StrictController::LOCAL_CLEAR_CAUGHT = "st_clear_caught";
const char* StrictController::LOCAL_PENALTY_LOG = "st_penalty_log";
const char* StrictController::LOCAL_PENALTY_REJECT = "st_penalty_reject";

StrictController::StrictController(void) {
}

int StrictController::enableStrict(void) {
    char connmarkFlagAccept[16];
    char connmarkFlagReject[16];
    char connmarkFlagTestAccept[32];
    char connmarkFlagTestReject[32];
    sprintf(connmarkFlagAccept, "0x%x", ConnmarkFlags::STRICT_RESOLVED_ACCEPT);
    sprintf(connmarkFlagReject, "0x%x", ConnmarkFlags::STRICT_RESOLVED_REJECT);
    sprintf(connmarkFlagTestAccept, "0x%x/0x%x",
            ConnmarkFlags::STRICT_RESOLVED_ACCEPT,
            ConnmarkFlags::STRICT_RESOLVED_ACCEPT);
    sprintf(connmarkFlagTestReject, "0x%x/0x%x",
            ConnmarkFlags::STRICT_RESOLVED_REJECT,
            ConnmarkFlags::STRICT_RESOLVED_REJECT);

    int res = 0;

    disableStrict();

    // Chain triggered when cleartext socket detected and penalty is log
    res |= execIptables(V4V6, "-N", LOCAL_PENALTY_LOG, NULL);
    res |= execIptables(V4V6, "-A", LOCAL_PENALTY_LOG,
            "-j", "CONNMARK", "--or-mark", connmarkFlagAccept, NULL);
    res |= execIptables(V4V6, "-A", LOCAL_PENALTY_LOG,
            "-j", "NFLOG", "--nflog-group", "0", NULL);

    // Chain triggered when cleartext socket detected and penalty is reject
    res |= execIptables(V4V6, "-N", LOCAL_PENALTY_REJECT, NULL);
    res |= execIptables(V4V6, "-A", LOCAL_PENALTY_REJECT,
            "-j", "CONNMARK", "--or-mark", connmarkFlagReject, NULL);
    res |= execIptables(V4V6, "-A", LOCAL_PENALTY_REJECT,
            "-j", "NFLOG", "--nflog-group", "0", NULL);
    res |= execIptables(V4V6, "-A", LOCAL_PENALTY_REJECT,
            "-j", "REJECT", NULL);

    // Create chain to detect non-TLS traffic. We use a high-order
    // mark bit to keep track of connections that we've already resolved.
    res |= execIptables(V4V6, "-N", LOCAL_CLEAR_DETECT, NULL);
    res |= execIptables(V4V6, "-N", LOCAL_CLEAR_CAUGHT, NULL);

    // Quickly skip connections that we've already resolved
    res |= execIptables(V4V6, "-A", LOCAL_CLEAR_DETECT,
            "-m", "connmark", "--mark", connmarkFlagTestReject,
            "-j", "REJECT", NULL);
    res |= execIptables(V4V6, "-A", LOCAL_CLEAR_DETECT,
            "-m", "connmark", "--mark", connmarkFlagTestAccept,
            "-j", "RETURN", NULL);

    // Look for IPv4 TCP/UDP connections with TLS/DTLS header
    res |= execIptables(V4, "-A", LOCAL_CLEAR_DETECT, "-p", "tcp",
            "-m", "u32", "--u32", "0>>22&0x3C@ 12>>26&0x3C@ 0&0xFFFF0000=0x16030000 &&"
                                  "0>>22&0x3C@ 12>>26&0x3C@ 4&0x00FF0000=0x00010000",
            "-j", "CONNMARK", "--or-mark", connmarkFlagAccept, NULL);
    res |= execIptables(V4, "-A", LOCAL_CLEAR_DETECT, "-p", "udp",
            "-m", "u32", "--u32", "0>>22&0x3C@ 8&0xFFFF0000=0x16FE0000 &&"
                                  "0>>22&0x3C@ 20&0x00FF0000=0x00010000",
            "-j", "CONNMARK", "--or-mark", connmarkFlagAccept, NULL);

    // Look for IPv6 TCP/UDP connections with TLS/DTLS header.  The IPv6 header
    // doesn't have an IHL field to shift with, so we have to manually add in
    // the 40-byte offset at every step.
    res |= execIptables(V6, "-A", LOCAL_CLEAR_DETECT, "-p", "tcp",
            "-m", "u32", "--u32", "52>>26&0x3C@ 40&0xFFFF0000=0x16030000 &&"
                                  "52>>26&0x3C@ 44&0x00FF0000=0x00010000",
            "-j", "CONNMARK", "--or-mark", connmarkFlagAccept, NULL);
    res |= execIptables(V6, "-A", LOCAL_CLEAR_DETECT, "-p", "udp",
            "-m", "u32", "--u32", "48&0xFFFF0000=0x16FE0000 &&"
                                  "60&0x00FF0000=0x00010000",
            "-j", "CONNMARK", "--or-mark", connmarkFlagAccept, NULL);

    // Skip newly classified connections from above
    res |= execIptables(V4V6, "-A", LOCAL_CLEAR_DETECT,
            "-m", "connmark", "--mark", connmarkFlagTestAccept,
            "-j", "RETURN", NULL);

    // Handle TCP/UDP payloads that didn't match TLS/DTLS filters above,
    // which means we've probably found cleartext data.  The TCP variant
    // depends on u32 returning false when we try reading into the message
    // body to ignore empty ACK packets.
    res |= execIptables(V4, "-A", LOCAL_CLEAR_DETECT, "-p", "tcp",
            "-m", "state", "--state", "ESTABLISHED",
            "-m", "u32", "--u32", "0>>22&0x3C@ 12>>26&0x3C@ 0&0x0=0x0",
            "-j", LOCAL_CLEAR_CAUGHT, NULL);
    res |= execIptables(V6, "-A", LOCAL_CLEAR_DETECT, "-p", "tcp",
            "-m", "state", "--state", "ESTABLISHED",
            "-m", "u32", "--u32", "52>>26&0x3C@ 40&0x0=0x0",
            "-j", LOCAL_CLEAR_CAUGHT, NULL);

    res |= execIptables(V4V6, "-A", LOCAL_CLEAR_DETECT, "-p", "udp",
            "-j", LOCAL_CLEAR_CAUGHT, NULL);

    return res;
}

int StrictController::disableStrict(void) {
    int res = 0;

    // Flush any existing rules
    res |= execIptables(V4V6, "-F", LOCAL_OUTPUT, NULL);

    res |= execIptables(V4V6, "-F", LOCAL_PENALTY_LOG, NULL);
    res |= execIptables(V4V6, "-F", LOCAL_PENALTY_REJECT, NULL);
    res |= execIptables(V4V6, "-F", LOCAL_CLEAR_CAUGHT, NULL);
    res |= execIptables(V4V6, "-F", LOCAL_CLEAR_DETECT, NULL);

    res |= execIptables(V4V6, "-X", LOCAL_PENALTY_LOG, NULL);
    res |= execIptables(V4V6, "-X", LOCAL_PENALTY_REJECT, NULL);
    res |= execIptables(V4V6, "-X", LOCAL_CLEAR_CAUGHT, NULL);
    res |= execIptables(V4V6, "-X", LOCAL_CLEAR_DETECT, NULL);

    return res;
}

int StrictController::setUidCleartextPenalty(uid_t uid, StrictPenalty penalty) {
    char uidStr[16];
    sprintf(uidStr, "%d", uid);

    int res = 0;
    if (penalty == ACCEPT) {
        // Clean up any old rules
        execIptables(V4V6, "-D", LOCAL_OUTPUT,
                "-m", "owner", "--uid-owner", uidStr,
                "-j", LOCAL_CLEAR_DETECT, NULL);
        execIptables(V4V6, "-D", LOCAL_CLEAR_CAUGHT,
                "-m", "owner", "--uid-owner", uidStr,
                "-j", LOCAL_PENALTY_LOG, NULL);
        execIptables(V4V6, "-D", LOCAL_CLEAR_CAUGHT,
                "-m", "owner", "--uid-owner", uidStr,
                "-j", LOCAL_PENALTY_REJECT, NULL);

    } else {
        // Always take a detour to investigate this UID
        res |= execIptables(V4V6, "-I", LOCAL_OUTPUT,
                "-m", "owner", "--uid-owner", uidStr,
                "-j", LOCAL_CLEAR_DETECT, NULL);

        if (penalty == LOG) {
            res |= execIptables(V4V6, "-I", LOCAL_CLEAR_CAUGHT,
                    "-m", "owner", "--uid-owner", uidStr,
                    "-j", LOCAL_PENALTY_LOG, NULL);
        } else if (penalty == REJECT) {
            res |= execIptables(V4V6, "-I", LOCAL_CLEAR_CAUGHT,
                    "-m", "owner", "--uid-owner", uidStr,
                    "-j", LOCAL_PENALTY_REJECT, NULL);
        }
    }

    return res;
}
