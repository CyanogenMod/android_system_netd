/* Copyright (c) 2010-2013, The Linux Foundation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 *     * Neither the name of The Linux Foundation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#define LOG_NDEBUG 0
#define LOG_NDDEBUG 0
#define LOG_NIDEBUG 0

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/types.h>

#include <cutils/log.h>
#include "RouteController.h"

const char *TAG = "RouteController";
static char IP_PATH[] = "/system/bin/ip";
const char *RouteController::MAIN_TABLE = "254";
const int MAXSIZE = 256;


RouteController::RouteController() {
}

RouteController::~RouteController() {
}

std::string RouteController::_runIpCmd(const char * cmd) {
    FILE *fp = NULL;
    char line[MAXSIZE];
    std::string res, buffer;

    if (strlen(cmd) > 255) {
        return std::string(strerror(E2BIG));
    }

    buffer = IP_PATH;
    buffer += " ";
    buffer += cmd;
    buffer += " 2>&1"; //capture stderr

    ALOGV(TAG,"%s", buffer.c_str());

    if ((fp = popen(buffer.c_str(),"r")) == NULL) {
        ALOGE(TAG, "failed to popen: %s", strerror(errno));
        res = (strerror(errno));
    } else if (fgets(line, sizeof line, fp)) {
        ALOGV(TAG, "%s", line);
        res = cmd;
        res += ": ";
        res += line;
    }
    pclose(fp);

    return res;
}

std::string RouteController::repSrcRoute
(
    const char *iface,
    const char *srcPrefix,
    const char *gateway,
    const char *table,
    const char *ipver
)
{
    std::string res = _repDefRoute(iface, gateway, table, ipver);
    if (res.empty()) {
        _delRule(table, ipver);
        res = _addRule(srcPrefix, table, ipver);
        if (res.empty())
            res = _flushCache();
    }

    return res;
}

std::string RouteController::delSrcRoute
(
    const char *table,
    const char *ipver
)
{
    //if iface is down then route is probably purged; ignore the error.
    _delDefRoute(table, ipver);
    std::string res = _delRule(table, ipver);
    if (res.empty())
        res = _flushCache();

    return res;
}

std::string RouteController::addDstRoute
(
    const char *iface,
    const char *dstPrefix,
    const char *gateway,
    const int metric,
    const char *table
)
{
    char buffer[255];

    if (gateway) {
        snprintf(buffer, sizeof buffer,
                 "route add %s via %s dev %s table %s metric %d",
                 dstPrefix, gateway, iface, table, metric);
    } else {
        snprintf(buffer, sizeof buffer,
                 "route add %s dev %s table %s metric %d",
                 dstPrefix, iface, table, metric);
    }

    //blindly delete an indentical route if it exists.
    _delHostRoute(dstPrefix, table);

    std::string res  = _runIpCmd(buffer);
    if (res.empty() || (res.find("exists") != std::string::npos))
        res = _flushCache();

    return res;
}

std::string RouteController::delDstRoute
(
    const char *dstPrefix,
    const char *table
)
{
    std::string res = _delHostRoute(dstPrefix, table);
    if (res.empty())
        res = _flushCache();

    return res;
}

std::string RouteController::_delHostRoute
(
    const char *dstPrefix,
    const char *table
)
{
    char buffer[255];
    snprintf(buffer, sizeof buffer, "route del %s table %s",
             dstPrefix, table);

    return _runIpCmd(buffer);
}

std::string RouteController::replaceDefRoute
(
    const char *iface,
    const char *gateway,
    const char *ipver
)
{
    std::string res = _repDefRoute(iface, gateway, MAIN_TABLE, ipver);
    if (res.empty())
        res = _flushCache();

    return res;
}

std::string RouteController::_repDefRoute
(
    const char *iface,
    const char *gateway,
    const char *table,
    const char *ipver
)
{
    char buffer[255];

    if (gateway) {
        snprintf(buffer, sizeof buffer,
                 "%s route replace default via %s dev %s scope global table %s",
                 ipver, gateway, iface, table);
    } else {
        snprintf(buffer, sizeof buffer,
                 "%s route replace default dev %s table %s",
                 ipver, iface, table);
    }

    return _runIpCmd(buffer);
}

std::string RouteController::_delDefRoute
(
    const char *table,
    const char *ipver,
    const char *iface
)
{
    char buffer[255];

    if (iface) {
        snprintf(buffer, sizeof buffer,
                "%s route del default dev %s table %s",
                ipver, iface, table);
    } else {
        snprintf(buffer, sizeof buffer,
                "%s route del default table %s", ipver, table);
    }

    return _runIpCmd(buffer);
}

std::string RouteController::addDefRoute
(
    const char *iface,
    const char *gateway,
    const char *ipver,
    const int metric,
    const char *table
)
{
    char buffer[255];

    //remove existing def route for an iface before adding one with new metric
    _delDefRoute(table, ipver, iface);

    if (gateway) {
        snprintf(buffer, sizeof buffer,
                 "%s route add default via %s dev %s table %s metric %d",
                 ipver, gateway, iface, table, metric);
    } else {
        snprintf(buffer, sizeof buffer,
                 "%s route add default dev %s table %s metric %d",
                 ipver, iface, table, metric);
    }

    std::string res = _runIpCmd(buffer);
    if (res.empty())
        res = _flushCache();

    return res;
}

std::string RouteController::_flushCache() {
    char buffer[255];

    snprintf(buffer, sizeof buffer, "route flush cached");

    return _runIpCmd(buffer);
}

std::string RouteController::_addRule
(
    const char *address,
    const char *table,
    const char *ipver
)
{
    char buffer[255];

    snprintf(buffer, sizeof buffer,
            "%s rule add from %s lookup %s", ipver, address, table);

    return _runIpCmd(buffer);
}

std::string RouteController::_delRule
(
    const char *table,
    const char *ipver
)
{
    char buffer[255];

    snprintf(buffer, sizeof buffer,
             "%s rule del table %s", ipver, table);

    return _runIpCmd(buffer);
}
