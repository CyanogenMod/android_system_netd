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

#include "FwmarkServer.h"

#include "Fwmark.h"
#include "FwmarkCommand.h"
#include "NetworkController.h"
#include "resolv_netid.h"

#include <sys/socket.h>
#include <unistd.h>

FwmarkServer::FwmarkServer(NetworkController* networkController) :
        SocketListener("fwmarkd", true), mNetworkController(networkController) {
}

bool FwmarkServer::onDataAvailable(SocketClient* client) {
    int fd = -1;
    int error = processClient(client, &fd);
    if (fd >= 0) {
        close(fd);
    }

    // Always send a response even if there were connection errors or read errors, so that we don't
    // inadvertently cause the client to hang (which always waits for a response).
    client->sendData(&error, sizeof(error));

    // Always close the client connection (by returning false). This prevents a DoS attack where
    // the client issues multiple commands on the same connection, never reading the responses,
    // causing its receive buffer to fill up, and thus causing our client->sendData() to block.
    return false;
}

int FwmarkServer::processClient(SocketClient* client, int* fd) {
    FwmarkCommand command;

    iovec iov;
    iov.iov_base = &command;
    iov.iov_len = sizeof(command);

    msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_iov = &iov;
    message.msg_iovlen = 1;

    union {
        cmsghdr cmh;
        char cmsg[CMSG_SPACE(sizeof(*fd))];
    } cmsgu;

    memset(cmsgu.cmsg, 0, sizeof(cmsgu.cmsg));
    message.msg_control = cmsgu.cmsg;
    message.msg_controllen = sizeof(cmsgu.cmsg);

    int messageLength = TEMP_FAILURE_RETRY(recvmsg(client->getSocket(), &message, 0));
    if (messageLength <= 0) {
        return -errno;
    }

    if (messageLength != sizeof(command)) {
        return -EBADMSG;
    }

    cmsghdr* const cmsgh = CMSG_FIRSTHDR(&message);
    if (cmsgh && cmsgh->cmsg_level == SOL_SOCKET && cmsgh->cmsg_type == SCM_RIGHTS &&
        cmsgh->cmsg_len == CMSG_LEN(sizeof(*fd))) {
        memcpy(fd, CMSG_DATA(cmsgh), sizeof(*fd));
    }

    if (*fd < 0) {
        return -EBADF;
    }

    Fwmark fwmark;
    socklen_t fwmarkLen = sizeof(fwmark.intValue);
    if (getsockopt(*fd, SOL_SOCKET, SO_MARK, &fwmark.intValue, &fwmarkLen) == -1) {
        return -errno;
    }

    Permission permission = mNetworkController->getPermissionForUser(client->getUid());

    switch (command.cmdId) {
        case FwmarkCommand::ON_ACCEPT: {
            // Called after a socket accept(). The kernel would've marked the netId and necessary
            // permissions bits, so we just add the rest of the user's permissions here.
            permission = static_cast<Permission>(permission | fwmark.permission);
            break;
        }

        case FwmarkCommand::ON_CONNECT: {
            // Set the netId (of the default network) into the fwmark, if it has not already been
            // set explicitly. Called before a socket connect() happens.
            if (!fwmark.explicitlySelected) {
                fwmark.netId = mNetworkController->getDefaultNetwork();
            }
            break;
        }

        case FwmarkCommand::SELECT_NETWORK: {
            fwmark.netId = command.netId;
            if (command.netId == NETID_UNSET) {
                fwmark.explicitlySelected = false;
            } else {
                fwmark.explicitlySelected = true;
                // If the socket already has the protectedFromVpn bit set, don't reset it, because
                // non-CONNECTIVITY_INTERNAL apps (e.g.: VpnService) may also protect sockets.
                if (permission & PERMISSION_CONNECTIVITY_INTERNAL) {
                    fwmark.protectedFromVpn = true;
                }
                if (!mNetworkController->isValidNetwork(command.netId)) {
                    return -ENONET;
                }
                if (!mNetworkController->isUserPermittedOnNetwork(client->getUid(),
                                                                  command.netId)) {
                    return -EPERM;
                }
            }
            break;
        }

        case FwmarkCommand::PROTECT_FROM_VPN: {
            // set vpn protect
            // TODO
            break;
        }

        default: {
            // unknown command
            return -EPROTO;
        }
    }

    fwmark.permission = permission;

    if (setsockopt(*fd, SOL_SOCKET, SO_MARK, &fwmark.intValue, sizeof(fwmark.intValue)) == -1) {
        return -errno;
    }

    return 0;
}
