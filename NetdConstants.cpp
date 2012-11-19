/*
 * Copyright (C) 2012 The Android Open Source Project
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

#include <string.h>

#define LOG_TAG "Netd"

#include <cutils/log.h>

#include "NetdConstants.h"

const char * const OEM_SCRIPT_PATH = "/system/bin/oem-iptables-init.sh";
const char * const IPTABLES_PATH = "/system/bin/iptables";
const char * const IP6TABLES_PATH = "/system/bin/ip6tables";
const char * const TC_PATH = "/system/bin/tc";
const char * const IP_PATH = "/system/bin/ip";
const char * const ADD = "add";
const char * const DEL = "del";

static void logExecError(const char* argv[], int res) {
    const char** argp = argv;
    std::string args = "";
    while (*argp) {
        args += *argp;
        args += ' ';
        argp++;
    }
    ALOGE("exec() res=%d for %s", res, args.c_str());
}

static int execIptables(IptablesTarget target, bool silent, va_list args) {
    /* Read arguments from incoming va_list; we expect the list to be NULL terminated. */
    std::list<const char*> argsList;
    argsList.push_back(NULL);
    const char* arg;
    do {
        arg = va_arg(args, const char *);
        argsList.push_back(arg);
    } while (arg);

    int i = 0;
    const char* argv[argsList.size()];
    std::list<const char*>::iterator it;
    for (it = argsList.begin(); it != argsList.end(); it++, i++) {
        argv[i] = *it;
    }

    int res = 0;
    if (target == V4 || target == V4V6) {
        argv[0] = IPTABLES_PATH;
        int localRes = fork_and_execve(argv[0], argv);
        if (localRes) {
            if (!silent) {
                logExecError(argv, localRes);
            }
            res |= localRes;
        }
    }
    if (target == V6 || target == V4V6) {
        argv[0] = IP6TABLES_PATH;
        int localRes = fork_and_execve(argv[0], argv);
        if (localRes) {
            if (!silent) {
                logExecError(argv, localRes);
            }
            res |= localRes;
        }
    }
    return res;
}

int execIptables(IptablesTarget target, ...) {
    va_list args;
    va_start(args, target);
    int res = execIptables(target, false, args);
    va_end(args);
    return res;
}

int execIptablesSilently(IptablesTarget target, ...) {
    va_list args;
    va_start(args, target);
    int res = execIptables(target, true, args);
    va_end(args);
    return res;
}
