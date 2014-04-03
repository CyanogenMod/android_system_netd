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

#ifndef _DNSPROXYLISTENER_H__
#define _DNSPROXYLISTENER_H__

#include <sysutils/FrameworkListener.h>

#include "NetdCommand.h"
#include "NetworkController.h"

class DnsProxyListener : public FrameworkListener {
public:
    DnsProxyListener(const NetworkController* controller);
    virtual ~DnsProxyListener() {}

private:
    const NetworkController *mNetCtrl;
    class GetAddrInfoCmd : public NetdCommand {
    public:
        GetAddrInfoCmd(const NetworkController* controller);
        virtual ~GetAddrInfoCmd() {}
        int runCommand(SocketClient *c, int argc, char** argv);
    private:
        const NetworkController* mNetCtrl;
    };

    class GetAddrInfoHandler {
    public:
        // Note: All of host, service, and hints may be NULL
        GetAddrInfoHandler(SocketClient *c,
                           char* host,
                           char* service,
                           struct addrinfo* hints,
                           unsigned netId);
        ~GetAddrInfoHandler();

        static void* threadStart(void* handler);
        void start();

    private:
        void run();
        SocketClient* mClient;  // ref counted
        char* mHost;    // owned
        char* mService; // owned
        struct addrinfo* mHints;  // owned
        unsigned mNetId;
    };

    /* ------ gethostbyname ------*/
    class GetHostByNameCmd : public NetdCommand {
    public:
        GetHostByNameCmd(const NetworkController* controller);
        virtual ~GetHostByNameCmd() {}
        int runCommand(SocketClient *c, int argc, char** argv);
    private:
        const NetworkController* mNetCtrl;
    };

    class GetHostByNameHandler {
    public:
        GetHostByNameHandler(SocketClient *c,
                            char *name,
                            int af,
                            unsigned netId);
        ~GetHostByNameHandler();
        static void* threadStart(void* handler);
        void start();
    private:
        void run();
        SocketClient* mClient; //ref counted
        char* mName; // owned
        int mAf;
        unsigned mNetId;
    };

    /* ------ gethostbyaddr ------*/
    class GetHostByAddrCmd : public NetdCommand {
    public:
        GetHostByAddrCmd(const NetworkController* controller);
        virtual ~GetHostByAddrCmd() {}
        int runCommand(SocketClient *c, int argc, char** argv);
    private:
        const NetworkController* mNetCtrl;
    };

    class GetHostByAddrHandler {
    public:
        GetHostByAddrHandler(SocketClient *c,
                            void* address,
                            int addressLen,
                            int addressFamily,
                            unsigned netId);
        ~GetHostByAddrHandler();

        static void* threadStart(void* handler);
        void start();

    private:
        void run();
        SocketClient* mClient;  // ref counted
        void* mAddress;    // address to lookup; owned
        int mAddressLen; // length of address to look up
        int mAddressFamily;  // address family
        unsigned mNetId;
    };
};

#endif
