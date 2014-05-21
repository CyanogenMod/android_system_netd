/*
 * Copyright (C) 2014 The Android Open Source Project
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

#include "NetdClient.h"

#include "FwmarkClient.h"
#include "FwmarkCommand.h"
#include "resolv_netid.h"

#include <sys/socket.h>
#include <unistd.h>

namespace {

int closeFdAndRestoreErrno(int fd) {
    int error = errno;
    close(fd);
    errno = error;
    return -1;
}

typedef int (*ConnectFunctionType)(int, const sockaddr*, socklen_t);
typedef int (*AcceptFunctionType)(int, sockaddr*, socklen_t*);
typedef unsigned (*NetIdForResolvFunctionType)(unsigned);

// These variables are only modified at startup (when libc.so is loaded) and never afterwards, so
// it's okay that they are read later at runtime without a lock.
ConnectFunctionType libcConnect = 0;
AcceptFunctionType libcAccept = 0;

int netdClientConnect(int sockfd, const sockaddr* addr, socklen_t addrlen) {
    if (FwmarkClient::shouldSetFwmark(sockfd, addr)) {
        FwmarkCommand command = {FwmarkCommand::ON_CONNECT, 0};
        if (!FwmarkClient().send(&command, sizeof(command), sockfd)) {
            return -1;
        }
    }
    return libcConnect(sockfd, addr, addrlen);
}

int netdClientAccept(int sockfd, sockaddr* addr, socklen_t* addrlen) {
    int acceptedSocket = libcAccept(sockfd, addr, addrlen);
    if (acceptedSocket == -1) {
        return -1;
    }
    sockaddr socketAddress;
    if (!addr) {
        socklen_t socketAddressLen = sizeof(socketAddress);
        if (getsockname(acceptedSocket, &socketAddress, &socketAddressLen) == -1) {
            return closeFdAndRestoreErrno(acceptedSocket);
        }
        addr = &socketAddress;
    }
    if (FwmarkClient::shouldSetFwmark(acceptedSocket, addr)) {
        FwmarkCommand command = {FwmarkCommand::ON_ACCEPT, 0};
        if (!FwmarkClient().send(&command, sizeof(command), acceptedSocket)) {
            return closeFdAndRestoreErrno(acceptedSocket);
        }
    }
    return acceptedSocket;
}

// TODO: Convert to C++11 std::atomic<unsigned>.
volatile sig_atomic_t netIdForProcess = NETID_UNSET;
volatile sig_atomic_t netIdForResolv = NETID_UNSET;

unsigned getNetworkForResolv(unsigned netId) {
    if (netId != NETID_UNSET) {
        return netId;
    }
    netId = netIdForProcess;
    if (netId != NETID_UNSET) {
        return netId;
    }
    return netIdForResolv;
}

bool setNetworkForTarget(unsigned netId, volatile sig_atomic_t* target) {
    if (netId == NETID_UNSET) {
        *target = netId;
        return true;
    }
    // Verify that we are allowed to use |netId|, by creating a socket and trying to have it marked
    // with the netId. Don't create an AF_INET socket, because then the creation itself might cause
    // another check with the fwmark server (see netdClientSocket()), which would be wasteful.
    int socketFd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (socketFd < 0) {
        return false;
    }
    bool status = setNetworkForSocket(netId, socketFd);
    closeFdAndRestoreErrno(socketFd);
    if (status) {
        *target = netId;
    }
    return status;
}

}  // namespace

extern "C" void netdClientInitConnect(ConnectFunctionType* function) {
    if (function && *function) {
        libcConnect = *function;
        *function = netdClientConnect;
    }
}

extern "C" void netdClientInitAccept(AcceptFunctionType* function) {
    if (function && *function) {
        libcAccept = *function;
        *function = netdClientAccept;
    }
}

extern "C" void netdClientInitNetIdForResolv(NetIdForResolvFunctionType* function) {
    if (function) {
        *function = getNetworkForResolv;
    }
}

extern "C" unsigned getNetworkForProcess() {
    return netIdForProcess;
}

extern "C" bool setNetworkForSocket(unsigned netId, int socketFd) {
    if (socketFd < 0) {
        errno = EBADF;
        return false;
    }
    FwmarkCommand command = {FwmarkCommand::SELECT_NETWORK, netId};
    return FwmarkClient().send(&command, sizeof(command), socketFd);
}

extern "C" bool setNetworkForProcess(unsigned netId) {
    return setNetworkForTarget(netId, &netIdForProcess);
}

extern "C" bool setNetworkForResolv(unsigned netId) {
    return setNetworkForTarget(netId, &netIdForResolv);
}
