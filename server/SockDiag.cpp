/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>

#define LOG_TAG "Netd"

#include <cutils/log.h>

#include "NetdConstants.h"
#include "SockDiag.h"

#include <chrono>

#ifndef SOCK_DESTROY
#define SOCK_DESTROY 21
#endif

namespace {

struct AddrinfoDeleter {
  void operator()(addrinfo *a) { if (a) freeaddrinfo(a); }
};

typedef std::unique_ptr<addrinfo, AddrinfoDeleter> ScopedAddrinfo;

int checkError(int fd) {
    struct {
        nlmsghdr h;
        nlmsgerr err;
    } __attribute__((__packed__)) ack;
    ssize_t bytesread = recv(fd, &ack, sizeof(ack), MSG_DONTWAIT | MSG_PEEK);
    if (bytesread == -1) {
       // Read failed (error), or nothing to read (good).
       return (errno == EAGAIN) ? 0 : -errno;
    } else if (bytesread == (ssize_t) sizeof(ack) && ack.h.nlmsg_type == NLMSG_ERROR) {
        // We got an error. Consume it.
        recv(fd, &ack, sizeof(ack), 0);
        return ack.err.error;
    } else {
        // The kernel replied with something. Leave it to the caller.
        return 0;
    }
}

}  // namespace

bool SockDiag::open() {
    if (hasSocks()) {
        return false;
    }

    mSock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_INET_DIAG);
    mWriteSock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_INET_DIAG);
    if (!hasSocks()) {
        closeSocks();
        return false;
    }

    sockaddr_nl nl = { .nl_family = AF_NETLINK };
    if ((connect(mSock, reinterpret_cast<sockaddr *>(&nl), sizeof(nl)) == -1) ||
        (connect(mWriteSock, reinterpret_cast<sockaddr *>(&nl), sizeof(nl)) == -1)) {
        closeSocks();
        return false;
    }

    return true;
}

int SockDiag::sendDumpRequest(uint8_t proto, uint8_t family, const char *addrstr) {
    addrinfo hints = { .ai_flags = AI_NUMERICHOST };
    addrinfo *res;
    in6_addr mapped = { .s6_addr32 = { 0, 0, htonl(0xffff), 0 } };
    int ret;

    // TODO: refactor the netlink parsing code out of system/core, bring it into netd, and stop
    // doing string conversions when they're not necessary.
    if ((ret = getaddrinfo(addrstr, nullptr, &hints, &res)) != 0) {
        return -EINVAL;
    }

    // So we don't have to call freeaddrinfo on every failure path.
    ScopedAddrinfo resP(res);

    void *addr;
    uint8_t addrlen;
    if (res->ai_family == AF_INET && family == AF_INET) {
        in_addr& ina = reinterpret_cast<sockaddr_in*>(res->ai_addr)->sin_addr;
        addr = &ina;
        addrlen = sizeof(ina);
    } else if (res->ai_family == AF_INET && family == AF_INET6) {
        in_addr& ina = reinterpret_cast<sockaddr_in*>(res->ai_addr)->sin_addr;
        mapped.s6_addr32[3] = ina.s_addr;
        addr = &mapped;
        addrlen = sizeof(mapped);
    } else if (res->ai_family == AF_INET6 && family == AF_INET6) {
        in6_addr& in6a = reinterpret_cast<sockaddr_in6*>(res->ai_addr)->sin6_addr;
        addr = &in6a;
        addrlen = sizeof(in6a);
    } else {
        return -EAFNOSUPPORT;
    }

    uint8_t prefixlen = addrlen * 8;
    uint8_t yesjump = sizeof(inet_diag_bc_op) + sizeof(inet_diag_hostcond) + addrlen;
    uint8_t nojump = yesjump + 4;
    uint32_t states = ~(1 << TCP_TIME_WAIT);

    struct {
        nlmsghdr nlh;
        inet_diag_req_v2 req;
        nlattr nla;
        inet_diag_bc_op op;
        inet_diag_hostcond cond;
    } __attribute__((__packed__)) request = {
        .nlh = {
            .nlmsg_type = SOCK_DIAG_BY_FAMILY,
            .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
        },
        .req = {
            .sdiag_family = family,
            .sdiag_protocol = proto,
            .idiag_states = states,
        },
        .nla = {
            .nla_type = INET_DIAG_REQ_BYTECODE,
        },
        .op = {
            INET_DIAG_BC_S_COND,
            yesjump,
            nojump,
        },
        .cond = {
            family,
            prefixlen,
            -1,
            {}
        },
    };

    request.nlh.nlmsg_len = sizeof(request) + addrlen;
    request.nla.nla_len = sizeof(request.nla) + sizeof(request.op) + sizeof(request.cond) + addrlen;

    struct iovec iov[] = {
        { &request, sizeof(request) },
        { addr, addrlen },
    };

    if (writev(mSock, iov, ARRAY_SIZE(iov)) != (int) request.nlh.nlmsg_len) {
        return -errno;
    }

    return checkError(mSock);
}

int SockDiag::readDiagMsg(uint8_t proto, SockDiag::DumpCallback callback) {
    char buf[kBufferSize];

    ssize_t bytesread;
    do {
        bytesread = read(mSock, buf, sizeof(buf));

        if (bytesread < 0) {
            return -errno;
        }

        uint32_t len = bytesread;
        for (nlmsghdr *nlh = reinterpret_cast<nlmsghdr *>(buf);
             NLMSG_OK(nlh, len);
             nlh = NLMSG_NEXT(nlh, len)) {
            switch (nlh->nlmsg_type) {
              case NLMSG_DONE:
                callback(proto, NULL);
                return 0;
              case NLMSG_ERROR: {
                nlmsgerr *err = reinterpret_cast<nlmsgerr *>(NLMSG_DATA(nlh));
                return err->error;
              }
              default:
                inet_diag_msg *msg = reinterpret_cast<inet_diag_msg *>(NLMSG_DATA(nlh));
                callback(proto, msg);
            }
        }
    } while (bytesread > 0);

    return 0;
}

int SockDiag::sockDestroy(uint8_t proto, const inet_diag_msg *msg) {
    if (msg == nullptr) {
       return 0;
    }

    DestroyRequest request = {
        .nlh = {
            .nlmsg_type = SOCK_DESTROY,
            .nlmsg_flags = NLM_F_REQUEST,
        },
        .req = {
            .sdiag_family = msg->idiag_family,
            .sdiag_protocol = proto,
            .idiag_states = (uint32_t) (1 << msg->idiag_state),
            .id = msg->id,
        },
    };
    request.nlh.nlmsg_len = sizeof(request);

    if (write(mWriteSock, &request, sizeof(request)) < (ssize_t) sizeof(request)) {
        return -errno;
    }

    int ret = checkError(mWriteSock);
    if (!ret) mSocketsDestroyed++;
    return ret;
}

int SockDiag::destroySockets(uint8_t proto, int family, const char *addrstr) {
    if (!hasSocks()) {
        return -EBADFD;
    }

    if (int ret = sendDumpRequest(proto, family, addrstr)) {
        return ret;
    }

    auto destroy = [this] (uint8_t proto, const inet_diag_msg *msg) {
        return this->sockDestroy(proto, msg);
    };

    return readDiagMsg(proto, destroy);
}

int SockDiag::destroySockets(const char *addrstr) {
    using ms = std::chrono::duration<float, std::ratio<1, 1000>>;

    mSocketsDestroyed = 0;
    const auto start = std::chrono::steady_clock::now();
    if (!strchr(addrstr, ':')) {
        if (int ret = destroySockets(IPPROTO_TCP, AF_INET, addrstr)) {
            ALOGE("Failed to destroy IPv4 sockets on %s: %s", addrstr, strerror(-ret));
            return ret;
        }
    }
    if (int ret = destroySockets(IPPROTO_TCP, AF_INET6, addrstr)) {
        ALOGE("Failed to destroy IPv6 sockets on %s: %s", addrstr, strerror(-ret));
        return ret;
    }
    auto elapsed = std::chrono::duration_cast<ms>(std::chrono::steady_clock::now() - start);

    if (mSocketsDestroyed > 0) {
        ALOGI("Destroyed %d sockets on %s in %.1f ms", mSocketsDestroyed, addrstr, elapsed.count());
    }

    return mSocketsDestroyed;
}
