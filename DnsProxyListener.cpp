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
}

DnsProxyListener::GetAddrInfoHandler::~GetAddrInfoHandler() {
    free(mHost);
    free(mService);
    free(mHints);
}

void DnsProxyListener::GetAddrInfoHandler::start() {
    pthread_create(&mThread, NULL,
                   DnsProxyListener::GetAddrInfoHandler::threadStart, this);
}

void* DnsProxyListener::GetAddrInfoHandler::threadStart(void* obj) {
    GetAddrInfoHandler* handler = reinterpret_cast<GetAddrInfoHandler*>(obj);
    handler->run();
    delete handler;
    pthread_exit(NULL);
    return NULL;
}

// Sends 4 bytes of big-endian length, followed by the data.
// Returns true on success.
static bool sendLenAndData(SocketClient *c, const int len, const void* data) {
    uint32_t len_be = htonl(len);
    return c->sendData(&len_be, 4) == 0 && c->sendData(data, len) == 0;
}

void DnsProxyListener::GetAddrInfoHandler::run() {
    if (DBG) {
        LOGD("GetAddrInfoHandler, now for %s / %s", mHost, mService);
    }

    struct addrinfo* result = NULL;
    int rv = getaddrinfo(mHost, mService, mHints, &result);
    bool success = mClient->sendData(&rv, sizeof(rv));
    if (rv == 0) {
        struct addrinfo* ai = result;
        while (ai && success) {
            success = sendLenAndData(mClient, sizeof(struct addrinfo), ai)
                && sendLenAndData(mClient, ai->ai_addrlen, ai->ai_addr)
                && sendLenAndData(mClient,
                                  ai->ai_canonname ? strlen(ai->ai_canonname) + 1 : 0,
                                  ai->ai_canonname);
            ai = ai->ai_next;
        }
        success = success && sendLenAndData(mClient, 0, "");
    }
    if (result) {
        freeaddrinfo(result);
    }
    if (!success) {
        LOGW("Error writing DNS result to client");
    }
}

DnsProxyListener::GetAddrInfoCmd::GetAddrInfoCmd() :
    NetdCommand("getaddrinfo") {
}

int DnsProxyListener::GetAddrInfoCmd::runCommand(SocketClient *cli,
                                            int argc, char **argv) {
    if (argc != 7) {
        LOGW("Invalid number of arguments to getaddrinfo");
        return 0;
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
        LOGD("GetAddrInfoHandler for %s / %s",
             name ? name : "[nullhost]",
             service ? service : "[nullservice]");
    }

    DnsProxyListener::GetAddrInfoHandler* handler =
        new DnsProxyListener::GetAddrInfoHandler(cli, name, service, hints);
    handler->start();


    return 0;
}
