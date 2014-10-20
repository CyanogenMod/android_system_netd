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

#include "Fwmark.h"
#include "NetdConstants.h"
#include "Permission.h"
#include "TetherController.h"

#include <private/android_filesystem_config.h>
#include <unistd.h>

#define RTRADVDAEMON "/system/bin/radish"
#define IP4_CFG_IP_FORWARD          "/proc/sys/net/ipv4/ip_forward"
#define IP6_CFG_ALL_PROXY_NDP       "/proc/sys/net/ipv6/conf/all/proxy_ndp"
#define IP6_CFG_ALL_FORWARDING      "/proc/sys/net/ipv6/conf/all/forwarding"
#define IP6_IFACE_CFG_ACCEPT_RA     "/proc/sys/net/ipv6/conf/%s/accept_ra"
#define PROC_PATH_SIZE              255
#define RTRADVDAEMON_MIN_IFACES     2
#define MAX_TABLE_LEN               11
#define MIN_TABLE_NUMBER            0
#define IP_ADDR                     "ip addr"
#define BASE_TABLE_NUMBER           1000
#define IF_INDEX_PATH               "/sys/class/net/%s/ifindex"
#define SYS_PATH_SIZE               PROC_PATH_SIZE

/* This is the number of arguments for RTRADVDAEMON which accounts for the
 * location of the daemon, the table name option, the name of the table
 * and a final empty string
 */
#define RTRADVDAEMON_ARGS_COUNT     4

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
    if (write(fd, value, strlen(value)) != (int)strlen(value)) {
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

#define TETHER_START_CONST_ARG        8

int TetherController::startTethering(int num_addrs, struct in_addr* addrs) {
    if (mDaemonPid != 0) {
        ALOGE("Tethering already started");
        errno = EBUSY;
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

        int num_processed_args = TETHER_START_CONST_ARG + (num_addrs/2) + 1;
        char **args = (char **)malloc(sizeof(char *) * num_processed_args);
        args[num_processed_args - 1] = NULL;
        args[0] = (char *)"/system/bin/dnsmasq";
        args[1] = (char *)"--keep-in-foreground";
        args[2] = (char *)"--no-resolv";
        args[3] = (char *)"--no-poll";
        args[4] = (char *)"--dhcp-authoritative";
        // TODO: pipe through metered status from ConnService
        args[5] = (char *)"--dhcp-option-force=43,ANDROID_METERED";
        args[6] = (char *)"--pid-file";
        args[7] = (char *)"";

        int nextArg = TETHER_START_CONST_ARG;
        for (int addrIndex=0; addrIndex < num_addrs;) {
            char *start = strdup(inet_ntoa(addrs[addrIndex++]));
            char *end = strdup(inet_ntoa(addrs[addrIndex++]));
            asprintf(&(args[nextArg++]),"--dhcp-range=%s,%s,1h", start, end);
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
        applyDnsInterfaces();
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

int TetherController::startV6RtrAdv(int num_ifaces, char **ifaces, int table_number) {
    int pid;
    int num_processed_args = 1;
    gid_t groups [] = { AID_NET_ADMIN, AID_NET_RAW, AID_INET };

    if (num_ifaces < RTRADVDAEMON_MIN_IFACES) {
        ALOGD("Need atleast two interfaces to start Router advertisement daemon");
        return 0;
    }

    if ((pid = fork()) < 0) {
        ALOGE("%s: fork failed (%s)", __func__, strerror(errno));
        return -1;
    }
    if (!pid) {
        char **args;
        const char *cmd = RTRADVDAEMON;

        args = (char **)calloc(num_ifaces * 3 + RTRADVDAEMON_ARGS_COUNT, sizeof(char *));
        if (!args) {
          ALOGE("%s: failed to allocate memory", __func__);
          return -1;
        }

        args[0] = strdup(RTRADVDAEMON);
        int aidx = 0;
        for (int i=0; i < num_ifaces; i++) {
            aidx = 3 * i + num_processed_args;
            args[aidx++] = (char *)"-i";
            args[aidx++] = ifaces[i];
            args[aidx++] = (char *)"-x";
        }
        if (table_number > MIN_TABLE_NUMBER) {
          char table_name[MAX_TABLE_LEN];
          unsigned int retval =  0;
          table_number += BASE_TABLE_NUMBER;
          retval = snprintf(table_name, sizeof(table_name), "%d", table_number);
          if (retval >= sizeof(table_name)) {
            ALOGE("%s: String truncation occured", __func__);
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

int TetherController::getIfaceIndexForIface(const char *iface)
{
   FILE *fp = NULL;
   char res[MAX_TABLE_LEN];
   int iface_num = -1;
   char if_index[SYS_PATH_SIZE];
   unsigned int retval = 0;
   if (iface == NULL)
   {
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
   if (fp == NULL)
   {
     ALOGE("%s() Cannot read file : path %s, error %s", __func__, if_index, strerror(errno));
     return iface_num;
   }

   memset(res, 0, sizeof(res));
   while (fgets(res, sizeof(res)-1, fp) != NULL)
   {
      ALOGD("%s() %s", __func__, res);
      iface_num = atoi(res);
      ALOGD("%s() Interface index for interface %s is %d", __func__, iface, iface_num);
   }

   fclose(fp);
   return iface_num;
}

/* Stop and start the ipv6 router advertisement daemon with the updated
 * interfaces. Pass the table number as a command line argument when
 * tethering is enabled.
 */
int TetherController::configureV6RtrAdv() {
    char **args;
    int i;
    int len;
    InterfaceCollection::iterator it;
    int iface_index = -1;
    /* For now, just stop and start the daemon with the new interface list */

    len = mInterfaces->size() + mUpstreamInterfaces->size();
    args = (char **)calloc(len, sizeof(char *));

    if (!args) {
        errno = ENOMEM;
        return -1;
    }

    for (i = 0, it = mInterfaces->begin(); it != mInterfaces->end(); it++, i++) {
        args[i] = *it;
    }

    for (it = mUpstreamInterfaces->begin(); i < len && it != mUpstreamInterfaces->end(); it++, i++)
    {
        args[i] = *it;
        iface_index = getIfaceIndexForIface(args[i]);
        ALOGD("%s: Upstream Iface: %s iface index: %d", __func__, args[i], iface_index);
    }

    stopV6RtrAdv();
    startV6RtrAdv(i, args, iface_index);

    free(args);

    return 0;
}

bool TetherController::isV6RtrAdvStarted() {
    return (mRtrAdvPid == 0 ? false : true);
}

#define MAX_CMD_SIZE 1024

int TetherController::setDnsForwarders(unsigned netId, char **servers, int numServers) {
    int i;
    char daemonCmd[MAX_CMD_SIZE];

    Fwmark fwmark;
    fwmark.netId = netId;
    fwmark.explicitlySelected = true;
    fwmark.protectedFromVpn = true;
    fwmark.permission = PERMISSION_SYSTEM;

    snprintf(daemonCmd, sizeof(daemonCmd), "update_dns:0x%x", fwmark.intValue);
    int cmdLen = strlen(daemonCmd);

    mDnsForwarders->clear();
    for (i = 0; i < numServers; i++) {
        ALOGD("setDnsForwarders(0x%x %d = '%s')", fwmark.intValue, i, servers[i]);

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

    mDnsNetId = netId;
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

unsigned TetherController::getDnsNetId() {
    return mDnsNetId;
}

int TetherController::addUpstreamInterface(char *iface)
{
    InterfaceCollection::iterator it;

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

    return configureV6RtrAdv();
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
            return configureV6RtrAdv();
        }
    }

    ALOGW("Couldn't find interface %s to remove", iface);
    return 0;
}

NetAddressCollection *TetherController::getDnsForwarders() {
    return mDnsForwarders;
}

int TetherController::applyDnsInterfaces() {
    char daemonCmd[MAX_CMD_SIZE];

    strcpy(daemonCmd, "update_ifaces");
    int cmdLen = strlen(daemonCmd);
    InterfaceCollection::iterator it;
    bool haveInterfaces = false;

    for (it = mInterfaces->begin(); it != mInterfaces->end(); ++it) {
        cmdLen += (strlen(*it) + 1);
        if (cmdLen + 1 >= MAX_CMD_SIZE) {
            ALOGD("Too many DNS ifaces listed");
            break;
        }

        strcat(daemonCmd, ":");
        strcat(daemonCmd, *it);
        haveInterfaces = true;
    }

    if ((mDaemonFd != -1) && haveInterfaces) {
        ALOGD("Sending update msg to dnsmasq [%s]", daemonCmd);
        if (write(mDaemonFd, daemonCmd, strlen(daemonCmd) +1) < 0) {
            ALOGE("Failed to send update command to dnsmasq (%s)", strerror(errno));
            return -1;
        }
    }
    return 0;
}

int TetherController::tetherInterface(const char *interface) {
    ALOGD("tetherInterface(%s)", interface);
    if (!isIfaceName(interface)) {
        errno = ENOENT;
        return -1;
    }
    mInterfaces->push_back(strdup(interface));

    configureV6RtrAdv();

    if (applyDnsInterfaces()) {
        InterfaceCollection::iterator it;
        for (it = mInterfaces->begin(); it != mInterfaces->end(); ++it) {
            if (!strcmp(interface, *it)) {
                free(*it);
                mInterfaces->erase(it);
                break;
            }
        }
        return -1;
    } else {
        return 0;
    }
}

int TetherController::untetherInterface(const char *interface) {
    InterfaceCollection::iterator it;

    ALOGD("untetherInterface(%s)", interface);

    for (it = mInterfaces->begin(); it != mInterfaces->end(); ++it) {
        if (!strcmp(interface, *it)) {
            free(*it);
            mInterfaces->erase(it);
            configureV6RtrAdv();
            return applyDnsInterfaces();
        }
    }
    errno = ENOENT;
    return -1;
}

InterfaceCollection *TetherController::getTetheredInterfaceList() {
    return mInterfaces;
}
