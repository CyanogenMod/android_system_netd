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

class DnsProxyListener : public FrameworkListener {
public:
    DnsProxyListener();
    virtual ~DnsProxyListener() {}

private:
    class GetAddrInfoCmd : public NetdCommand {
    public:
        GetAddrInfoCmd();
        virtual ~GetAddrInfoCmd() {}
        int runCommand(SocketClient *c, int argc, char** argv);
    };

    class GetAddrInfoHandler {
    public:
        // Note: All of host, service, and hints may be NULL
        GetAddrInfoHandler(SocketClient *c,
                           char* host,
                           char* service,
                           struct addrinfo* hints)
            : mClient(c),
              mHost(host),
              mService(service),
              mHints(hints) {}
        ~GetAddrInfoHandler();

        static void* threadStart(void* handler);
        void start();

    private:
        void run();
        SocketClient* mClient;  // ref counted
        char* mHost;    // owned
        char* mService; // owned
        struct addrinfo* mHints;  // owned
    };

    /* ------ gethostbyaddr ------*/
    class GetHostByAddrCmd : public NetdCommand {
    public:
        GetHostByAddrCmd();
        virtual ~GetHostByAddrCmd() {}
        int runCommand(SocketClient *c, int argc, char** argv);
    };

    class GetHostByAddrHandler {
    public:
        GetHostByAddrHandler(SocketClient *c,
                            void* address,
                            int   addressLen,
                            int   addressFamily)
            : mClient(c),
              mAddress(address),
              mAddressLen(addressLen),
              mAddressFamily(addressFamily) {}
        ~GetHostByAddrHandler();

        static void* threadStart(void* handler);
        void start();

    private:
        void run();
        SocketClient* mClient;  // ref counted
        void* mAddress;    // address to lookup; owned
        int   mAddressLen; // length of address to look up
        int   mAddressFamily;  // address family
    };
};

#endif
