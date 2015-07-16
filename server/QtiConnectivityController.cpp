/*
   Copyright (c) 2015, The Linux Foundation. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above
      copyright notice, this list of conditions and the following
      disclaimer in the documentation and/or other materials provided
      with the distribution.
    * Neither the name of The Linux Foundation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
*/

#define LOG_NDEBUG 0
#define LOG_TAG "QtiConnectivityController"
#include <cutils/log.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sysutils/SocketClient.h>
#include <sys/wait.h>
#include <unistd.h>

#include <private/android_filesystem_config.h>
#include "QtiConnectivityController.h"
#include "NetdCommand.h"
#include "ResponseCode.h"

const char* QtiConnectivityController::INTENT_COMMAND =
        "am broadcast -a com.qualcomm.qti.TETHER_IPV4_CHANGED";
const char* QtiConnectivityController::INTENT_STRING_EXTRA_OPT =
        "--es";
const char* QtiConnectivityController::INTENT_TETHER_IFACE_EXTRA_KEY =
        "tether_iface";
const char* QtiConnectivityController::INTENT_UPSTREAM_IFACE_EXTRA_KEY =
        "upstream_iface";
const char* QtiConnectivityController::INTENT_INCLUDE_STOPPED_PACKAGES =
        "--include-stopped-packages";

const char* QtiConnectivityController::QtiTetherCommand::IF_INDEX_PATH =
        "/sys/class/net/%s/ifindex";
const char* QtiConnectivityController::QtiTetherCommand::IP6_CFG_ALL_PROXY_NDP =
        "/proc/sys/net/ipv6/conf/all/proxy_ndp";
const char* QtiConnectivityController::QtiTetherCommand::IP6_CFG_ALL_FORWARDING =
        "/proc/sys/net/ipv6/conf/all/forwarding";
const char* QtiConnectivityController::QtiTetherCommand::RTRADVDAEMON =
        "/system/bin/radish";

QtiConnectivityController::QtiConnectivityController() {
    ALOGI("%s()", __func__);
    mTetherCmd = NULL;
}

QtiConnectivityController::~QtiConnectivityController() {
    QtiTetherCommand *tetherCtl = getQtiTetherCommand();
    if (tetherCtl != NULL) {
        delete(tetherCtl);
    }
}

NetdCommand *QtiConnectivityController::getQtiConnectivityCmd() {
    return getQtiTetherCommand()->asNetdCommand();
}

void QtiConnectivityController::natStarted
(
    const char* tetherIface,
    const char* upstreamIface
) {
    ALOGI("%s(): Tether Interface: %s Upstream Iface: %s",
            __func__, tetherIface, upstreamIface);
    char cmd[INTENT_COMMAND_MAX_SIZE];
    memset(cmd, '\0', INTENT_COMMAND_MAX_SIZE);
    int cmd_len = snprintf(cmd, INTENT_COMMAND_MAX_SIZE, "%s %s %s %s %s %s %s %s",
            INTENT_COMMAND, INTENT_STRING_EXTRA_OPT, INTENT_TETHER_IFACE_EXTRA_KEY, tetherIface,
            INTENT_STRING_EXTRA_OPT, INTENT_UPSTREAM_IFACE_EXTRA_KEY, upstreamIface,
            INTENT_INCLUDE_STOPPED_PACKAGES);

    if (cmd_len >= INTENT_COMMAND_MAX_SIZE) {
        ALOGE("%s() String truncation occurred", __func__);
    } else {
        ALOGD("%s() cmd=%s", __func__, cmd);
        system(cmd);
    }
}

void QtiConnectivityController::natStopped
(
    const char* tetherIface,
    const char* upstreamIface
) {
    ALOGI("%s(): Tether Interface: %s Upstream Iface: %s",
            __func__, tetherIface, upstreamIface);
    char cmd[INTENT_COMMAND_MAX_SIZE];
    memset(cmd, '\0', INTENT_COMMAND_MAX_SIZE);
    int cmd_len = snprintf(cmd, INTENT_COMMAND_MAX_SIZE, "%s %s",
            INTENT_COMMAND, INTENT_INCLUDE_STOPPED_PACKAGES);

    if (cmd_len >= INTENT_COMMAND_MAX_SIZE) {
        ALOGE("%s() String truncation occurred", __func__);
    } else {
        ALOGD("%s() cmd=%s", __func__, cmd);
        system(cmd);
    }
}

QtiConnectivityController::QtiTetherCommand::QtiTetherCommand() : NetdCommand("qtitether") {
    mRtrAdvPid = -1;
}

QtiConnectivityController::QtiTetherCommand::~QtiTetherCommand() {
    stopRtrAdv();
}

int QtiConnectivityController::QtiTetherCommand::runCommand
(
    SocketClient *cli,
    int argc,
    char **argv
) {
    int rc = 0;
    if (argc < 2) {
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Missing argument", false);
        return 0;
    }

    //    0        1        2             3
    // qtitether stop
    // qtitether start tether_iface upstream_iface
    if (!strcmp(argv[1], "stop")) {
        rc = stopTethering();
    } else if (!strcmp(argv[1], "start") && argc >= 4) {
        rc = startTethering(argv[2], argv[3]);
    } else {
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Unknown qtitether cmd", false);
        return 0;
    }

    if (!rc) {
        cli->sendMsg(ResponseCode::CommandOkay, "Qtitether operation succeeded", false);
    } else {
        cli->sendMsg(ResponseCode::OperationFailed, "Qtitether operation failed", false);
    }

    return 0;
}

NetdCommand *QtiConnectivityController::QtiTetherCommand::asNetdCommand() {
    return static_cast<NetdCommand*>(this);
}

int QtiConnectivityController::QtiTetherCommand::startTethering
(
    const char* tetherIface,
    const char* upstreamIface
) {
    int ret_val = 0;
    char args[TETHER_ARGS_LEN][TETHER_IFACE_MAX_LEN];
    int iface_index = getIfaceIndexForIface(upstreamIface);
    ALOGI("%s(): Tether Interface: %s Upstream Iface: %s iface index: %d",
            __func__, tetherIface, upstreamIface, iface_index);

    if (setIpFwdEnabled(true)) {
        ret_val = -1;
    } else {
        memset(args[0], '\0', TETHER_IFACE_MAX_LEN);
        strncpy(args[0], tetherIface, TETHER_IFACE_MAX_LEN - 1);
        memset(args[1], '\0', TETHER_IFACE_MAX_LEN);
        strncpy(args[1], upstreamIface, TETHER_IFACE_MAX_LEN - 1);

        stopRtrAdv();
        ret_val = startRtrAdv(args[0], args[1], iface_index);
    }
    return ret_val;
}

int QtiConnectivityController::QtiTetherCommand::stopTethering() {
    ALOGI("%s()", __func__);
    stopRtrAdv();
    setIpFwdEnabled(false);
    return 0;
}

bool QtiConnectivityController::QtiTetherCommand::isRtrAdvStarted() {
    return (mRtrAdvPid > 0) ? true : false;
}

int QtiConnectivityController::QtiTetherCommand::startRtrAdv
(
    char* tetherIface,
    char* upstreamIface,
    int table_number
) {
    int pid;
    gid_t groups[] = { AID_NET_ADMIN, AID_NET_RAW, AID_INET };

    if ((pid = fork()) < 0) {
        ALOGE("%s: fork failed (%s)", __func__, strerror(errno));
        return -1;
    }
    if (!pid) {
        char **args;
        const char *cmd = RTRADVDAEMON;

        args = (char**)calloc(RTRADVDAEMON_ARGS_COUNT, sizeof(char*));
        if (!args) {
            ALOGE("%s(): failed to allocate memory", __func__);
            return -1;
        }

        int aidx = 0;
        args[aidx++] = strdup(RTRADVDAEMON);
        args[aidx++] = (char *)"-i";
        args[aidx++] = strdup(tetherIface);
        args[aidx++] = (char *)"-i";
        args[aidx++] = strdup(upstreamIface);
        args[aidx++] = (char *)"-x";

        if (table_number > MIN_TABLE_NUMBER) {
            char table_name[MAX_TABLE_LEN];
            unsigned int retval =  0;
            table_number += BASE_TABLE_NUMBER;
            retval = snprintf(table_name, sizeof(table_name), "%d", table_number);
            if (retval >= sizeof(table_name)) {
                ALOGE("%s(): String truncation occured", __func__);
            } else {
                args[aidx++] = (char *)"-t";
                args[aidx] = table_name;
            }
        }

        setgroups(sizeof(groups)/sizeof(groups[0]), groups);
        setresgid(AID_RADIO, AID_RADIO, AID_RADIO);
        setresuid(AID_RADIO, AID_RADIO, AID_RADIO);

        if (execv(cmd, args)) {
            ALOGE("Unable to exec %s: (%s)" , cmd, strerror(errno));
        }
        // strdup == malloc so must free all corresponding ptrs
        free(args[0]);
        free(args[2]);
        free(args[4]);
        free(args);
        exit(0);
    } else {
        mRtrAdvPid = pid;
        ALOGD("Router advertisement daemon running");
    }
    return 0;
}

int QtiConnectivityController::QtiTetherCommand::stopRtrAdv() {
    int ret_val = -1;
    if (isRtrAdvStarted()) {
        kill(mRtrAdvPid, SIGTERM);
        waitpid(mRtrAdvPid, NULL, 0);
        mRtrAdvPid = 0;
        ret_val = 0;
    }
    return ret_val;
}

int QtiConnectivityController::QtiTetherCommand::getIfaceIndexForIface(const char *iface) {
    FILE *fp = NULL;
    char res[MAX_TABLE_LEN];
    int iface_num = -1;
    char if_index[SYS_PATH_SIZE];
    unsigned int retval = 0;
    if (iface == NULL) {
        ALOGE("%s() Interface is NULL", __func__);
        return iface_num;
    }

    memset(if_index, 0, sizeof(if_index));
    retval = snprintf(if_index, sizeof(if_index), IF_INDEX_PATH, iface);
    if (retval >= sizeof(if_index)) {
        ALOGE("%s() String truncation occurred", __func__);
        return iface_num;
    }

    ALOGD("%s() File path is %s", __func__, if_index);
    fp = fopen(if_index, "r");
    if (fp == NULL) {
        ALOGE("%s() Cannot read file : path %s, error %s", __func__, if_index, strerror(errno));
        return iface_num;
    }

    memset(res, 0, sizeof(res));
    while (fgets(res, sizeof(res)-1, fp) != NULL) {
        ALOGD("%s() %s", __func__, res);
        iface_num = atoi(res);
        ALOGD("%s() Interface index for interface %s is %d", __func__, iface, iface_num);
    }

    fclose(fp);
    return iface_num;
}

int QtiConnectivityController::QtiTetherCommand::configWriteSetting
(
    const char *path,
    const char *value
) {
    int fd = open(path, O_WRONLY);

    ALOGD("configWriteSetting(%s, %s)", path, value);
    if (fd < 0) {
        ALOGE("Failed to open %s (%s)", path, strerror(errno));
        return -1;
    }
    if (((size_t) write(fd, value, strlen(value))) != strlen(value)) {
        ALOGE("Failed to write to %s (%s)", path, strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

int QtiConnectivityController::QtiTetherCommand::setIpFwdEnabled(bool enable) {
    if (configWriteSetting(
            IP6_CFG_ALL_PROXY_NDP, enable ? "2" : "0")) {
        ALOGE("Failed to write proxy_ndp (%s)", strerror(errno));
        return -1;
    }
    if (configWriteSetting(
            IP6_CFG_ALL_FORWARDING, enable ? "2" : "0")) {
        ALOGE("Failed to write ip6 forwarding (%s)", strerror(errno));
        return -1;
    }
    return 0;
}

QtiConnectivityController::QtiTetherCommand *QtiConnectivityController::getQtiTetherCommand() {
    if (mTetherCmd == NULL) {
        ALOGI("%s(): Creating Tether Command",
                __func__);
        mTetherCmd = new QtiTetherCommand();
        if (mTetherCmd == NULL) {
            ALOGE("%s(): Failure allocating Tether Command",
                    __func__);
        }
    }
    return mTetherCmd;
}
