/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless requied by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include <cutils/sockets.h>
#include <private/android_filesystem_config.h>
#include "NetdClient.h"

#include <gtest/gtest.h>
#define LOG_TAG "resolverTest"
#include <utils/Log.h>
#include <testUtil.h>

#include "dns_responder.h"

// TODO: make this dynamic and stop depending on implementation details.
#define TEST_OEM_NETWORK "oem29"
#define TEST_NETID 30

enum class ResponseCode : int {
    // Keep in sync with
    // frameworks/base/services/java/com/android/server/NetworkManagementService.java
    CommandOkay               = 200,
    DnsProxyQueryResult       = 222,

    DnsProxyOperationFailed   = 401,

    CommandSyntaxError        = 500,
    CommandParameterError     = 501
};


// Returns ResponseCode.
int netdCommand(const char* sockname, const char* command) {
    int sock = socket_local_client(sockname,
                                   ANDROID_SOCKET_NAMESPACE_RESERVED,
                                   SOCK_STREAM);
    if (sock < 0) {
        perror("Error connecting");
        return -1;
    }

    // FrameworkListener expects the whole command in one read.
    char buffer[256];
    int nwritten = snprintf(buffer, sizeof(buffer), "0 %s", command);
    if (write(sock, buffer, nwritten + 1) < 0) {
        perror("Error sending netd command");
        close(sock);
        return -1;
    }

    int nread = read(sock, buffer, sizeof(buffer));
    if (nread < 0) {
        perror("Error reading response");
        close(sock);
        return -1;
    }
    close(sock);
    return atoi(buffer);
}


bool expectNetdResult(ResponseCode code, const char* sockname, const char* format, ...) {
    char command[256];
    va_list args;
    va_start(args, format);
    vsnprintf(command, sizeof(command), format, args);
    va_end(args);
    int result = netdCommand(sockname, command);
    int rc = static_cast<int>(code);
    EXPECT_EQ(rc, result) << command;
    return (200 <= rc && rc < 300);
}


class ResolverTest : public ::testing::Test {
protected:
    virtual void SetUp() {
        // Ensure resolutions go via proxy.
        setenv("ANDROID_DNS_MODE", "", 1);
        uid = getuid();
        pid = getpid();
        SetupOemNetwork();
    }

    virtual void TearDown() {
        TearDownOemNetwork();
        netdCommand("netd", "network destroy " TEST_OEM_NETWORK);
    }

    void SetupOemNetwork() {
        netdCommand("netd", "network destroy " TEST_OEM_NETWORK);
        if (expectNetdResult(ResponseCode::CommandOkay, "netd",
                             "network create %s", TEST_OEM_NETWORK)) {
            oemNetId = TEST_NETID;
        }
        setNetworkForProcess(oemNetId);
        ASSERT_EQ((unsigned) oemNetId, getNetworkForProcess());
    }

    void TearDownOemNetwork() {
        if (oemNetId != -1) {
            expectNetdResult(ResponseCode::CommandOkay, "netd",
                             "network destroy %s", TEST_OEM_NETWORK);
        }
    }

    bool SetResolverForNetwork(const char* address) const {
        return
            expectNetdResult(ResponseCode::CommandOkay, "netd",
                             "resolver setnetdns %d \"example.com\" %s", oemNetId,
                             address) &&
            FlushCache();
    }

    bool FlushCache() const {
        return expectNetdResult(ResponseCode::CommandOkay, "netd",
                                "resolver flushnet %d", oemNetId);
    }

    std::string ToString(const hostent* result) const {
        if (result == nullptr) return std::string();
        return std::string(result->h_name);
    }

    std::string ToString(const addrinfo* result) const {
        if (!result)
            return "<null>";
        sockaddr_in* addr = reinterpret_cast<sockaddr_in*>(result->ai_addr);
        return std::string(inet_ntoa(addr->sin_addr));
    }

    int pid;
    int uid;
    int oemNetId = -1;
};


TEST_F(ResolverTest, GetHostByName) {
    const char* listen_addr = "127.0.0.3";
    const char* listen_srv = "53";
    test::DNSResponder resp(listen_addr, listen_srv, 250,
                            ns_rcode::ns_r_servfail);
    resp.addMapping("hello.example.com.", ns_type::ns_t_a, "1.2.3.3");
    ASSERT_TRUE(resp.startServer());
    ASSERT_TRUE(SetResolverForNetwork(listen_addr));

    resp.clearQueries();
    const hostent* result = gethostbyname("hello");
    auto queries = resp.queries();
    size_t found = 0;
    for (const auto& p : queries) {
        if (p.second == ns_type::ns_t_a && p.first == "hello.example.com.") {
            ++found;
        }
    }
    EXPECT_EQ(1, found);
    ASSERT_FALSE(result == nullptr);
    ASSERT_EQ(4, result->h_length);
    ASSERT_FALSE(result->h_addr_list[0] == nullptr);
    EXPECT_EQ("hello.example.com", ToString(result));
    EXPECT_TRUE(result->h_addr_list[1] == nullptr);
    resp.stopServer();
}

TEST_F(ResolverTest, GetAddrInfo) {
    addrinfo* result = nullptr;

    const char* listen_addr = "127.0.0.4";
    const char* listen_srv = "53";
    test::DNSResponder resp(listen_addr, listen_srv, 250,
                            ns_rcode::ns_r_servfail);
    resp.addMapping("howdie.example.com.", ns_type::ns_t_a, "1.2.3.4");
    resp.addMapping("howdie.example.com.", ns_type::ns_t_aaaa, "::1.2.3.4");
    ASSERT_TRUE(resp.startServer());
    ASSERT_TRUE(SetResolverForNetwork(listen_addr));

    resp.clearQueries();
    EXPECT_EQ(0, getaddrinfo("howdie", nullptr, nullptr, &result));
    auto queries = resp.queries();
    size_t found = 0;
    for (const auto& p : queries) {
        if (p.first == "howdie.example.com.") {
            ++found;
        }
    }
    EXPECT_LE(1, found);
    // Could be A or AAAA
    std::string result_str = ToString(result);
    EXPECT_TRUE(result_str == "1.2.3.4" || result_str == "::1.2.3.4");
    if (result) freeaddrinfo(result);
    result = nullptr;

    // Verify that it's cached.
    size_t old_found = found;
    EXPECT_EQ(0, getaddrinfo("howdie", nullptr, nullptr, &result));
    queries = resp.queries();
    found = 0;
    for (const auto& p : queries) {
        if (p.first == "howdie.example.com.") {
            ++found;
        }
    }
    EXPECT_EQ(old_found, found);
    result_str = ToString(result);
    EXPECT_TRUE(result_str == "1.2.3.4" || result_str == "::1.2.3.4");
    if (result) freeaddrinfo(result);
    result = nullptr;

    // Verify that cache can be flushed.
    resp.clearQueries();
    ASSERT_TRUE(FlushCache());
    resp.addMapping("howdie.example.com.", ns_type::ns_t_a, "1.2.3.44");
    resp.addMapping("howdie.example.com.", ns_type::ns_t_aaaa, "::1.2.3.44");

    EXPECT_EQ(0, getaddrinfo("howdie", nullptr, nullptr, &result));
    queries = resp.queries();
    found = 0;
    for (const auto& p : queries) {
        if (p.first == "howdie.example.com.") {
            ++found;
        }
    }
    EXPECT_LE(1, found);
    // Could be A or AAAA
    result_str = ToString(result);
    EXPECT_TRUE(result_str == "1.2.3.44" || result_str == "::1.2.3.44");
    if (result) freeaddrinfo(result);
}

TEST_F(ResolverTest, GetAddrInfoV4) {
    addrinfo* result = nullptr;

    const char* listen_addr = "127.0.0.5";
    const char* listen_srv = "53";
    test::DNSResponder resp(listen_addr, listen_srv, 250,
                            ns_rcode::ns_r_servfail);
    resp.addMapping("hola.example.com.", ns_type::ns_t_a, "1.2.3.5");
    ASSERT_TRUE(resp.startServer());
    ASSERT_TRUE(SetResolverForNetwork(listen_addr));

    addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    EXPECT_EQ(0, getaddrinfo("hola", nullptr, &hints, &result));
    auto queries = resp.queries();
    size_t found = 0;
    for (const auto& p : queries) {
        if (p.first == "hola.example.com.") {
            ++found;
        }
    }
    EXPECT_LE(1, found);
    EXPECT_EQ("1.2.3.5", ToString(result));
    if (result) freeaddrinfo(result);
}
