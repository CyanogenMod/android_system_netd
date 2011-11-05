/*
 * Copyright (C) 2010 The Android Open Source Project
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

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <linux/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>

#define LOG_TAG "DnsProxyListener"
#define DBG 0

#include <cutils/log.h>
#include <sysutils/SocketClient.h>

#include "DnsProxyListener.h"

DnsProxyListener::DnsProxyListener() :
                 FrameworkListener("dnsproxyd") {
    registerCmd(new GetAddrInfoCmd());
    registerCmd(new GetHostByAddrCmd());
}

// Sends 4 bytes of big-endian length, followed by the data.
// Returns true on success.
static bool sendLenAndData(SocketClient *c, const int len, const void* data) {
    uint32_t len_be = htonl(len);
    return c->sendData(&len_be, 4) == 0 &&
        (len == 0 || c->sendData(data, len) == 0);
}

DnsProxyListener::GetAddrInfoCmd::GetAddrInfoCmd() :
    NetdCommand("getaddrinfo") {
}

int DnsProxyListener::GetAddrInfoCmd::runCommand(SocketClient *cli,
                                            int argc, char **argv) {
    if (DBG) {
        for (int i = 0; i < argc; i++) {
            LOGD("argv[%i]=%s", i, argv[i]);
        }
    }
    if (argc != 7) {
        LOGW("Invalid number of arguments to getaddrinfo: %i", argc);
        sendLenAndData(cli, 0, NULL);
        return -1;
    }

    char* name = argv[1];
    if (strcmp("^", name) == 0) {
        name = NULL;
    } else {
        name = strdup(name);
    }

    char* service = argv[2];
    if (strcmp("^", service) == 0) {
        service = NULL;
    } else {
        service = strdup(service);
    }

    struct addrinfo* hints = NULL;
    int ai_flags = atoi(argv[3]);
    int ai_family = atoi(argv[4]);
    int ai_socktype = atoi(argv[5]);
    int ai_protocol = atoi(argv[6]);
    if (ai_flags != -1 || ai_family != -1 ||
        ai_socktype != -1 || ai_protocol != -1) {
        hints = (struct addrinfo*) calloc(1, sizeof(struct addrinfo));
        hints->ai_flags = ai_flags;
        hints->ai_family = ai_family;
        hints->ai_socktype = ai_socktype;
        hints->ai_protocol = ai_protocol;
    }

    if (DBG) {
        LOGD("GetAddrInfoCmd for %s / %s",
             name ? name : "[nullhost]",
             service ? service : "[nullservice]");
    }

    if (DBG) {
        LOGD("GetAddrInfoCmd, now for %s / %s", name, service);
    }

    struct addrinfo* result = NULL;
    int rv = getaddrinfo(name, service, hints, &result);
    bool success = (cli->sendData(&rv, sizeof(rv)) == 0);
    if (rv == 0) {
        struct addrinfo* ai = result;
        while (ai && success) {
            success = sendLenAndData(cli, sizeof(struct addrinfo), ai)
                && sendLenAndData(cli, ai->ai_addrlen, ai->ai_addr)
                && sendLenAndData(cli,
                                  ai->ai_canonname ? strlen(ai->ai_canonname) + 1 : 0,
                                  ai->ai_canonname);
            ai = ai->ai_next;
        }
        success = success && sendLenAndData(cli, 0, "");
    }
    if (result) {
        freeaddrinfo(result);
    }
    if (!success) {
        LOGW("Error writing DNS result to client");
    }

    return 0;
}

/*******************************************************
 *                  GetHostByAddr                       *
 *******************************************************/
DnsProxyListener::GetHostByAddrCmd::GetHostByAddrCmd() :
        NetdCommand("gethostbyaddr") {
}

int DnsProxyListener::GetHostByAddrCmd::runCommand(SocketClient *cli,
                                            int argc, char **argv) {
    if (DBG) {
        for (int i = 0; i < argc; i++) {
            LOGD("argv[%i]=%s", i, argv[i]);
        }
    }
    if (argc != 4) {
        LOGW("Invalid number of arguments to gethostbyaddr: %i", argc);
        sendLenAndData(cli, 0, NULL);
        return -1;
    }

    char* addrStr = argv[1];
    int addrLen = atoi(argv[2]);
    int addrFamily = atoi(argv[3]);

    void* addr = malloc(sizeof(struct in6_addr));
    errno = 0;
    int result = inet_pton(addrFamily, addrStr, addr);
    if (result <= 0) {
        LOGW("inet_pton(\"%s\") failed %s", addrStr, strerror(errno));
        free(addr);
        sendLenAndData(cli, 0, NULL);
        return -1;
    }

    struct hostent* hp;

    // NOTE gethostbyaddr should take a void* but bionic thinks it should be char*
    hp = gethostbyaddr((char*)addr, addrLen, addrFamily);

    if (DBG) {
        LOGD("GetHostByAddrCmd::runCommand gethostbyaddr errno: %s hp->h_name = %s, name_len = %d\n",
                hp ? "success" : strerror(errno),
                (hp && hp->h_name) ? hp->h_name: "null",
                (hp && hp->h_name) ? strlen(hp->h_name)+ 1 : 0);
    }

    bool success = sendLenAndData(cli, (hp && hp->h_name) ? strlen(hp->h_name)+ 1 : 0,
            (hp && hp->h_name) ? hp->h_name : "");


    if (!success) {
        LOGW("GetHostByAddrCmd: Error writing DNS result to client\n");
    }

    return 0;
}
