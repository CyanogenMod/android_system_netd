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
#include <string.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <linux/capability.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#define LOG_TAG "TetherController"
#define LOG_NDEBUG 0
#define LOG_NDDEBUG 0
#define LOG_NIDEBUG 0
#include <cutils/log.h>
#include <cutils/properties.h>

#include "TetherController.h"

#include <private/android_filesystem_config.h>
#include <unistd.h>

#define RTRADVDAEMON "/system/bin/radish"
#define IP4_CFG_IP_FORWARD          "/proc/sys/net/ipv4/ip_forward"
#define IP6_CFG_ALL_PROXY_NDP       "/proc/sys/net/ipv6/conf/all/proxy_ndp"
#define IP6_CFG_ALL_FORWARDING      "/proc/sys/net/ipv6/conf/all/forwarding"
#define IP6_IFACE_CFG_ACCEPT_RA     "/proc/sys/net/ipv6/conf/%s/accept_ra"
#define PROC_PATH_SIZE              255

TetherController::TetherController() {
    mInterfaces = new InterfaceCollection();
    mUpstreamInterfaces = new InterfaceCollection();
    mDnsForwarders = new NetAddressCollection();
    mDaemonFd = -1;
    mDaemonPid = 0;
}

TetherController::~TetherController() {
    InterfaceCollection::iterator it;

    for (it = mInterfaces->begin(); it != mInterfaces->end(); ++it) {
        free(*it);
    }
    mInterfaces->clear();

    for (it = mUpstreamInterfaces->begin(); it != mUpstreamInterfaces->end(); ++it) {
        free(*it);
    }
    mUpstreamInterfaces->clear();

    mDnsForwarders->clear();
}

static int config_write_setting(const char *path, const char *value)
{
    int fd = open(path, O_WRONLY);

    ALOGD("config_write_setting(%s, %s)", path, value);
    if (fd < 0) {
        ALOGE("Failed to open %s (%s)", path, strerror(errno));
        return -1;
    }
    if (write(fd, value, strlen(value)) != strlen(value)) {
        ALOGE("Failed to write to %s (%s)", path, strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

int TetherController::setIpFwdEnabled(bool enable) {

    ALOGD("Setting IP forward enable = %d", enable);

    // In BP tools mode, do not disable IP forwarding
    char bootmode[PROPERTY_VALUE_MAX] = {0};
    property_get("ro.bootmode", bootmode, "unknown");
    if ((enable == false) && (0 == strcmp("bp-tools", bootmode))) {
        return 0;
    }

    int fd = open("/proc/sys/net/ipv4/ip_forward", O_WRONLY);
    if (fd < 0) {
        ALOGE("Failed to open ip_forward (%s)", strerror(errno));
        return -1;
    }

    if (write(fd, (enable ? "1" : "0"), 1) != 1) {
        ALOGE("Failed to write ip_forward (%s)", strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);
    if (config_write_setting(
            IP6_CFG_ALL_PROXY_NDP, enable ? "2" : "0")) {
        ALOGE("Failed to write proxy_ndp (%s)", strerror(errno));
        return -1;
    }
    if (config_write_setting(
            IP6_CFG_ALL_FORWARDING, enable ? "2" : "0")) {
        ALOGE("Failed to write ip6 forwarding (%s)", strerror(errno));
        return -1;
    }

    return 0;
}

bool TetherController::getIpFwdEnabled() {
    int fd = open("/proc/sys/net/ipv4/ip_forward", O_RDONLY);

    if (fd < 0) {
        ALOGE("Failed to open ip_forward (%s)", strerror(errno));
        return false;
    }

    char enabled;
    if (read(fd, &enabled, 1) != 1) {
        ALOGE("Failed to read ip_forward (%s)", strerror(errno));
        close(fd);
        return -1;
    }

    close(fd);
    return (enabled  == '1' ? true : false);
}

int TetherController::startTethering(int num_addrs, struct in_addr* addrs, int lease_time) {
    if (mDaemonPid != 0) {
        ALOGE("Tethering already started");
        errno = EBUSY;
        return -1;
    }

    if (lease_time <= 0) {
        ALOGE("Invalid lease time %d!\n", lease_time);
        return -1;
    }

    ALOGD("Starting tethering services");

    pid_t pid;
    int pipefd[2];

    if (pipe(pipefd) < 0) {
        ALOGE("pipe failed (%s)", strerror(errno));
        return -1;
    }

    /*
     * TODO: Create a monitoring thread to handle and restart
     * the daemon if it exits prematurely
     */
    if ((pid = fork()) < 0) {
        ALOGE("fork failed (%s)", strerror(errno));
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (!pid) {
        close(pipefd[1]);
        if (pipefd[0] != STDIN_FILENO) {
            if (dup2(pipefd[0], STDIN_FILENO) != STDIN_FILENO) {
                ALOGE("dup2 failed (%s)", strerror(errno));
                return -1;
            }
            close(pipefd[0]);
        }

        int num_processed_args = 7 + (num_addrs/2) + 1; // 1 null for termination
        char **args = (char **)malloc(sizeof(char *) * num_processed_args);
        args[num_processed_args - 1] = NULL;
        args[0] = (char *)"/system/bin/dnsmasq";
        args[1] = (char *)"--keep-in-foreground";
        args[2] = (char *)"--no-resolv";
        args[3] = (char *)"--no-poll";
        // TODO: pipe through metered status from ConnService
        args[4] = (char *)"--dhcp-option-force=43,ANDROID_METERED";
        args[5] = (char *)"--pid-file";
        args[6] = (char *)"";

        int nextArg = 7;
        for (int addrIndex=0; addrIndex < num_addrs;) {
            char *start = strdup(inet_ntoa(addrs[addrIndex++]));
            char *end = strdup(inet_ntoa(addrs[addrIndex++]));
            asprintf(&(args[nextArg++]),"--dhcp-range=%s,%s,%d", start, end, lease_time);
        }

        if (execv(args[0], args)) {
            ALOGE("execl failed (%s)", strerror(errno));
        }
        ALOGE("Should never get here!");
        _exit(-1);
    } else {
        close(pipefd[0]);
        mDaemonPid = pid;
        mDaemonFd = pipefd[1];
        ALOGD("Tethering services running");
    }

    return 0;
}

int TetherController::stopTethering() {

    if (mDaemonPid == 0) {
        ALOGE("Tethering already stopped");
        return 0;
    }

    ALOGD("Stopping tethering services");

    kill(mDaemonPid, SIGTERM);
    waitpid(mDaemonPid, NULL, 0);
    mDaemonPid = 0;
    close(mDaemonFd);
    mDaemonFd = -1;
    ALOGD("Tethering services stopped");
    return 0;
}

bool TetherController::isTetheringStarted() {
    return (mDaemonPid == 0 ? false : true);
}


int TetherController::startV6RtrAdv(int num_ifaces, char **ifaces) {
    int pid;
    int num_processed_args = 1;
    gid_t groups [] = { AID_NET_ADMIN, AID_NET_RAW, AID_INET };

    if ((pid = fork()) < 0) {
        ALOGE("%s: fork failed (%s)", __func__, strerror(errno));
        return -1;
    }
    if (!pid) {
        char **args;
        const char *cmd = RTRADVDAEMON;

        args = (char **)calloc(num_ifaces * 3 + 2, sizeof(char *));

        args[0] = strdup(RTRADVDAEMON);
        for (int i=0; i < num_ifaces; i++) {
            int aidx = 3 * i + num_processed_args;
            args[aidx] = (char *)"-i";
            args[aidx + 1] = ifaces[i];
            args[aidx + 2] = (char *)"-x";
        }


        setgroups(sizeof(groups)/sizeof(groups[0]), groups);
        setresgid(AID_RADIO, AID_RADIO, AID_RADIO);
        setresuid(AID_RADIO, AID_RADIO, AID_RADIO);

        if (execv(cmd, args)) {
            ALOGE("Unable to exec %s: (%s)" , cmd, strerror(errno));
        }
        free(args[0]);
        free(args);
        exit(0);
    } else {
        mRtrAdvPid = pid;
        ALOGD("Router advertisement daemon running");
    }
    return 0;
}

int TetherController::stopV6RtrAdv() {
    if (!mRtrAdvPid) {
        ALOGD("Router advertisement daemon already stopped");
        return 0;
    }

    kill(mRtrAdvPid, SIGTERM);
    waitpid(mRtrAdvPid, NULL, 0);
    mRtrAdvPid = 0;
    ALOGD("Router advertisement daemon stopped");
    return 0;
}

int TetherController::addV6RtrAdvIface(const char *iface) {
    char **args;
    int i;
    int len;
    InterfaceCollection::iterator it;
    /* For now, just stop and start the daemon with the new interface list */

    len = mInterfaces->size() + mUpstreamInterfaces->size();
    ALOGD("addV6RtrAdvIface: len = %d. Iface: %s\n", len, iface);
    args = (char **)calloc(len, sizeof(char *));

    if (!args) {
        errno = ENOMEM;
        return -1;
    }

    for (i = 0, it = mInterfaces->begin(); it != mInterfaces->end(); it++, i++) {
        args[i] = *it;
    }

    for (it = mUpstreamInterfaces->begin(); i < len && it != mUpstreamInterfaces->end(); it++, i++) {
        args[i] = *it;
    }

    stopV6RtrAdv();
    startV6RtrAdv(i, args);

    free(args);

    return 0;
}

int TetherController::removeV6RtrAdvIface(const char *iface) {
    /* For now, just call addV6RtrAdvIface, since that will stop and
     * start the daemon with the updated interfaces
     */
    return addV6RtrAdvIface(iface);
}
bool TetherController::isV6RtrAdvStarted() {
    return (mRtrAdvPid == 0 ? false : true);
}

#define MAX_CMD_SIZE 1024

int TetherController::setDnsForwarders(char **servers, int numServers) {
    int i;
    char daemonCmd[MAX_CMD_SIZE];

    strcpy(daemonCmd, "update_dns");
    int cmdLen = strlen(daemonCmd);

    mDnsForwarders->clear();
    for (i = 0; i < numServers; i++) {
        ALOGD("setDnsForwarders(%d = '%s')", i, servers[i]);

        struct in_addr a;

        if (!inet_aton(servers[i], &a)) {
            ALOGE("Failed to parse DNS server '%s'", servers[i]);
            mDnsForwarders->clear();
            return -1;
        }

        cmdLen += (strlen(servers[i]) + 1);
        if (cmdLen + 1 >= MAX_CMD_SIZE) {
            ALOGD("Too many DNS servers listed");
            break;
        }

        strcat(daemonCmd, ":");
        strcat(daemonCmd, servers[i]);
        mDnsForwarders->push_back(a);
    }

    if (mDaemonFd != -1) {
        ALOGD("Sending update msg to dnsmasq [%s]", daemonCmd);
        if (write(mDaemonFd, daemonCmd, strlen(daemonCmd) +1) < 0) {
            ALOGE("Failed to send update command to dnsmasq (%s)", strerror(errno));
            mDnsForwarders->clear();
            return -1;
        }
    }
    return 0;
}

NetAddressCollection *TetherController::getDnsForwarders() {
    return mDnsForwarders;
}


int TetherController::addUpstreamInterface(char *iface)
{
    InterfaceCollection::iterator it;
    int fd;

    ALOGD("addUpstreamInterface(%s)\n", iface);

    if (!iface) {
        ALOGE("addUpstreamInterface: received null interface");
        return 0;
    }
    for (it = mUpstreamInterfaces->begin(); it != mUpstreamInterfaces->end(); ++it) {
        ALOGD(".");
        if (*it && !strcmp(iface, *it)) {
            ALOGD("addUpstreamInterface: interface %s already present", iface);
            return 0;
        }
    }
    mUpstreamInterfaces->push_back(strdup(iface));

    return addV6RtrAdvIface(iface);
}

int TetherController::removeUpstreamInterface(char *iface)
{
    InterfaceCollection::iterator it;

    if (!iface) {
        ALOGE("removeUpstreamInterface: Null interface name received");
        return 0;
    }
    for (it = mUpstreamInterfaces->begin(); it != mUpstreamInterfaces->end(); ++it) {
        if (*it && !strcmp(iface, *it)) {
            free(*it);
            mUpstreamInterfaces->erase(it);
            return removeV6RtrAdvIface(iface);
        }
    }

    ALOGW("Couldn't find interface %s to remove", iface);
    return 0;
}

int TetherController::tetherInterface(const char *interface) {
    ALOGD("tetherInterface(%s)", interface);
    mInterfaces->push_back(strdup(interface));

    addV6RtrAdvIface(interface);
    return 0;
}

int TetherController::untetherInterface(const char *interface) {
    InterfaceCollection::iterator it;

    ALOGD("untetherInterface(%s)", interface);

    for (it = mInterfaces->begin(); it != mInterfaces->end(); ++it) {
        if (!strcmp(interface, *it)) {
            free(*it);
            mInterfaces->erase(it);

            return 0;
        }
    }
    errno = ENOENT;
    return -1;
}

InterfaceCollection *TetherController::getTetheredInterfaceList() {
    return mInterfaces;
}
