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

#ifndef _ROUTE_CONTROLLER_H
#define _ROUTE_CONTROLLER_H

#include <string.h>
#include <string>

class RouteController {
public:
    RouteController();
    virtual ~RouteController();

    std::string repSrcRoute
    (
        const char *iface,
        const char *srcPrefix,
        const char *gateway,
        const char *table,
        const char *ipver
    );
    std::string delSrcRoute
    (
        const char *table,
        const char *ipver
    );
    std::string addDstRoute
    (
        const char *iface,
        const char *dstPrefix,
        const char *gateway,
        const int metric,
        const char *table = MAIN_TABLE
    );
    std::string delDstRoute
    (
        const char *dstPrefix,
        const char *table = MAIN_TABLE
    );
    std::string replaceDefRoute
    (
        const char *iface,
        const char *gateway,
        const char *ipver
    );
    std::string addDefRoute
    (
        const char *iface,
        const char *gateway,
        const char *ipver,
        const int metric,
        const char *table = MAIN_TABLE
    );

private:
    const static char *MAIN_TABLE;

    std::string _runIpCmd
    (
        const char *cmd
    );
    std::string _flushCache();
    std::string _repDefRoute
    (
        const char *iface,
        const char *gateway,
        const char *table,
        const char *ipver
    );
    std::string _delDefRoute
    (
        const char *table,
        const char *ipver,
        const char *iface = NULL
    );
    std::string _delHostRoute
    (
        const char *dstPrefix,
        const char *table = MAIN_TABLE
    );
    std::string _addRule
    (
        const char *address,
        const char *table,
        const char *ipver
    );
    std::string _delRule
    (
        const char *table,
        const char *ipver
    );
};

#endif
