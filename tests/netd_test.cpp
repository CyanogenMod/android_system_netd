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
#include <unistd.h>

#include <cutils/sockets.h>
#include <android-base/stringprintf.h>
#include <private/android_filesystem_config.h>

#include <thread>

#include "NetdClient.h"

#include <gtest/gtest.h>
#define LOG_TAG "resolverTest"
#include <utils/Log.h>
#include <testUtil.h>

#include "dns_responder.h"
#include "resolv_params.h"

using android::base::StringPrintf;
using android::base::StringAppendF;

// TODO: make this dynamic and stop depending on implementation details.
#define TEST_OEM_NETWORK "oem29"
#define TEST_NETID 30

// The only response code used in this test, see
// frameworks/base/services/java/com/android/server/NetworkManagementService.java
// for others.
static constexpr int ResponseCodeOK = 200;

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


bool expectNetdResult(int expected, const char* sockname, const char* format, ...) {
    char command[256];
    va_list args;
    va_start(args, format);
    vsnprintf(command, sizeof(command), format, args);
    va_end(args);
    int result = netdCommand(sockname, command);
    EXPECT_EQ(expected, result) << command;
    return (200 <= expected && expected < 300);
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
        if (expectNetdResult(ResponseCodeOK, "netd",
                             "network create %s", TEST_OEM_NETWORK)) {
            oemNetId = TEST_NETID;
        }
        setNetworkForProcess(oemNetId);
        ASSERT_EQ((unsigned) oemNetId, getNetworkForProcess());
    }

    void TearDownOemNetwork() {
        if (oemNetId != -1) {
            expectNetdResult(ResponseCodeOK, "netd",
                             "network destroy %s", TEST_OEM_NETWORK);
        }
    }

    bool SetResolversForNetwork(const std::vector<std::string>& searchDomains,
            const std::vector<std::string>& servers, const std::string& params) {
        // No use case for empty domains / servers (yet).
        if (searchDomains.empty() || servers.empty()) return false;

        std::string cmd = StringPrintf("resolver setnetdns %d \"%s", oemNetId,
                searchDomains[0].c_str());
        for (size_t i = 1 ; i < searchDomains.size() ; ++i) {
            cmd += " ";
            cmd += searchDomains[i];
        }
        cmd += "\" ";

        cmd += servers[0];
        for (size_t i = 1 ; i < servers.size() ; ++i) {
            cmd += " ";
            cmd += servers[i];
        }

        if (!params.empty()) {
            cmd += " --params \"";
            cmd += params;
            cmd += "\"";
        }

        int rv = netdCommand("netd", cmd.c_str());
        std::cout << "command: '" << cmd << "', rv = " << rv << "\n";
        if (rv != ResponseCodeOK) {
            return false;
        }
        return true;
    }

    bool FlushCache() const {
        return expectNetdResult(ResponseCodeOK, "netd", "resolver flushnet %d", oemNetId);
    }

    std::string ToString(const hostent* he) const {
        if (he == nullptr) return "<null>";
        char buffer[INET6_ADDRSTRLEN];
        if (!inet_ntop(he->h_addrtype, he->h_addr_list[0], buffer, sizeof(buffer))) {
            return "<invalid>";
        }
        return buffer;
    }

    std::string ToString(const addrinfo* ai) const {
        if (!ai)
            return "<null>";
        for (const auto* aip = ai ; aip != nullptr ; aip = aip->ai_next) {
            char host[NI_MAXHOST];
            int rv = getnameinfo(aip->ai_addr, aip->ai_addrlen, host, sizeof(host), nullptr, 0,
                    NI_NUMERICHOST);
            if (rv != 0)
                return gai_strerror(rv);
            return host;
        }
        return "<invalid>";
    }

    size_t GetNumQueries(const test::DNSResponder& dns, const char* name) const {
        auto queries = dns.queries();
        size_t found = 0;
        for (const auto& p : queries) {
            std::cout << "query " << p.first << "\n";
            if (p.first == name) {
                ++found;
            }
        }
        return found;
    }

    size_t GetNumQueriesForType(const test::DNSResponder& dns, ns_type type,
            const char* name) const {
        auto queries = dns.queries();
        size_t found = 0;
        for (const auto& p : queries) {
            std::cout << "query " << p.first << "\n";
            if (p.second == type && p.first == name) {
                ++found;
            }
        }
        return found;
    }

    int pid;
    int uid;
    int oemNetId = -1;
    const std::vector<std::string> mDefaultSearchDomains = { "example.com" };
    // <sample validity in s> <success threshold in percent> <min samples> <max samples>
    const std::string mDefaultParams = "300 25 8 8";
};

TEST_F(ResolverTest, GetHostByName) {
    const char* listen_addr = "127.0.0.3";
    const char* listen_srv = "53";
    const char* host_name = "hello.example.com.";
    test::DNSResponder dns(listen_addr, listen_srv, 250, ns_rcode::ns_r_servfail, 1.0);
    dns.addMapping(host_name, ns_type::ns_t_a, "1.2.3.3");
    ASSERT_TRUE(dns.startServer());
    std::vector<std::string> servers = { listen_addr };
    ASSERT_TRUE(SetResolversForNetwork(mDefaultSearchDomains, servers, mDefaultParams));

    dns.clearQueries();
    const hostent* result = gethostbyname("hello");
    EXPECT_EQ(1U, GetNumQueriesForType(dns, ns_type::ns_t_a, host_name));
    ASSERT_FALSE(result == nullptr);
    ASSERT_EQ(4, result->h_length);
    ASSERT_FALSE(result->h_addr_list[0] == nullptr);
    EXPECT_EQ("1.2.3.3", ToString(result));
    EXPECT_TRUE(result->h_addr_list[1] == nullptr);
    dns.stopServer();
}

TEST_F(ResolverTest, GetAddrInfo) {
    addrinfo* result = nullptr;

    const char* listen_addr = "127.0.0.4";
    const char* listen_srv = "53";
    const char* host_name = "howdie.example.com.";
    test::DNSResponder dns(listen_addr, listen_srv, 250,
                           ns_rcode::ns_r_servfail, 1.0);
    dns.addMapping(host_name, ns_type::ns_t_a, "1.2.3.4");
    dns.addMapping(host_name, ns_type::ns_t_aaaa, "::1.2.3.4");
    ASSERT_TRUE(dns.startServer());
    std::vector<std::string> servers = { listen_addr };
    ASSERT_TRUE(SetResolversForNetwork(mDefaultSearchDomains, servers, mDefaultParams));

    dns.clearQueries();
    EXPECT_EQ(0, getaddrinfo("howdie", nullptr, nullptr, &result));
    size_t found = GetNumQueries(dns, host_name);
    EXPECT_LE(1U, found);
    // Could be A or AAAA
    std::string result_str = ToString(result);
    EXPECT_TRUE(result_str == "1.2.3.4" || result_str == "::1.2.3.4")
        << ", result_str='" << result_str << "'";
    if (result) freeaddrinfo(result);
    result = nullptr;

    // Verify that it's cached.
    size_t old_found = found;
    EXPECT_EQ(0, getaddrinfo("howdie", nullptr, nullptr, &result));
    found = GetNumQueries(dns, host_name);
    EXPECT_LE(1U, found);
    EXPECT_EQ(old_found, found);
    result_str = ToString(result);
    EXPECT_TRUE(result_str == "1.2.3.4" || result_str == "::1.2.3.4")
        << result_str;
    if (result) freeaddrinfo(result);
    result = nullptr;

    // Verify that cache can be flushed.
    dns.clearQueries();
    ASSERT_TRUE(FlushCache());
    dns.addMapping(host_name, ns_type::ns_t_a, "1.2.3.44");
    dns.addMapping(host_name, ns_type::ns_t_aaaa, "::1.2.3.44");

    EXPECT_EQ(0, getaddrinfo("howdie", nullptr, nullptr, &result));
    EXPECT_LE(1U, GetNumQueries(dns, host_name));
    // Could be A or AAAA
    result_str = ToString(result);
    EXPECT_TRUE(result_str == "1.2.3.44" || result_str == "::1.2.3.44")
        << ", result_str='" << result_str << "'";
    if (result) freeaddrinfo(result);
}

TEST_F(ResolverTest, GetAddrInfoV4) {
    addrinfo* result = nullptr;

    const char* listen_addr = "127.0.0.5";
    const char* listen_srv = "53";
    const char* host_name = "hola.example.com.";
    test::DNSResponder dns(listen_addr, listen_srv, 250,
                           ns_rcode::ns_r_servfail, 1.0);
    dns.addMapping(host_name, ns_type::ns_t_a, "1.2.3.5");
    ASSERT_TRUE(dns.startServer());
    std::vector<std::string> servers = { listen_addr };
    ASSERT_TRUE(SetResolversForNetwork(mDefaultSearchDomains, servers, mDefaultParams));

    addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    EXPECT_EQ(0, getaddrinfo("hola", nullptr, &hints, &result));
    EXPECT_EQ(1U, GetNumQueries(dns, host_name));
    EXPECT_EQ("1.2.3.5", ToString(result));
    if (result) freeaddrinfo(result);
}

TEST_F(ResolverTest, MultidomainResolution) {
    std::vector<std::string> searchDomains = { "example1.com", "example2.com", "example3.com" };
    const char* listen_addr = "127.0.0.6";
    const char* listen_srv = "53";
    const char* host_name = "nihao.example2.com.";
    test::DNSResponder dns(listen_addr, listen_srv, 250,
                           ns_rcode::ns_r_servfail, 1.0);
    dns.addMapping(host_name, ns_type::ns_t_a, "1.2.3.3");
    ASSERT_TRUE(dns.startServer());
    std::vector<std::string> servers = { listen_addr };
    ASSERT_TRUE(SetResolversForNetwork(searchDomains, servers, mDefaultParams));

    dns.clearQueries();
    const hostent* result = gethostbyname("nihao");
    EXPECT_EQ(1U, GetNumQueriesForType(dns, ns_type::ns_t_a, host_name));
    ASSERT_FALSE(result == nullptr);
    ASSERT_EQ(4, result->h_length);
    ASSERT_FALSE(result->h_addr_list[0] == nullptr);
    EXPECT_EQ("1.2.3.3", ToString(result));
    EXPECT_TRUE(result->h_addr_list[1] == nullptr);
    dns.stopServer();
}

TEST_F(ResolverTest, GetAddrInfoV6_failing) {
    addrinfo* result = nullptr;

    const char* listen_addr0 = "127.0.0.7";
    const char* listen_addr1 = "127.0.0.8";
    const char* listen_srv = "53";
    const char* host_name = "ohayou.example.com.";
    test::DNSResponder dns0(listen_addr0, listen_srv, 250,
                            ns_rcode::ns_r_servfail, 0.0);
    test::DNSResponder dns1(listen_addr1, listen_srv, 250,
                            ns_rcode::ns_r_servfail, 1.0);
    dns0.addMapping(host_name, ns_type::ns_t_aaaa, "2001:db8::5");
    dns1.addMapping(host_name, ns_type::ns_t_aaaa, "2001:db8::6");
    ASSERT_TRUE(dns0.startServer());
    ASSERT_TRUE(dns1.startServer());
    std::vector<std::string> servers = { listen_addr0, listen_addr1 };
    // <sample validity in s> <success threshold in percent> <min samples> <max samples>
    unsigned sample_validity = 300;
    int success_threshold = 25;
    int sample_count = 8;
    std::string params = StringPrintf("%u %d %d %d", sample_validity, success_threshold,
            sample_count, sample_count);
    ASSERT_TRUE(SetResolversForNetwork(mDefaultSearchDomains, servers, params));

    // Repeatedly perform resolutions for non-existing domains until MAXNSSAMPLES resolutions have
    // reached the dns0, which is set to fail. No more requests should then arrive at that server
    // for the next sample_lifetime seconds.
    // TODO: This approach is implementation-dependent, change once metrics reporting is available.
    addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET6;
    for (int i = 0 ; i < sample_count ; ++i) {
        std::string domain = StringPrintf("nonexistent%d", i);
        getaddrinfo(domain.c_str(), nullptr, &hints, &result);
    }
    // Due to 100% errors for all possible samples, the server should be ignored from now on and
    // only the second one used for all following queries, until NSSAMPLE_VALIDITY is reached.
    dns0.clearQueries();
    dns1.clearQueries();
    EXPECT_EQ(0, getaddrinfo("ohayou", nullptr, &hints, &result));
    EXPECT_EQ(0U, GetNumQueries(dns0, host_name));
    EXPECT_EQ(1U, GetNumQueries(dns1, host_name));
    if (result) freeaddrinfo(result);
}

TEST_F(ResolverTest, GetAddrInfoV6_concurrent) {
    const char* listen_addr0 = "127.0.0.9";
    const char* listen_addr1 = "127.0.0.10";
    const char* listen_addr2 = "127.0.0.11";
    const char* listen_srv = "53";
    const char* host_name = "konbanha.example.com.";
    test::DNSResponder dns0(listen_addr0, listen_srv, 250,
                            ns_rcode::ns_r_servfail, 1.0);
    test::DNSResponder dns1(listen_addr1, listen_srv, 250,
                            ns_rcode::ns_r_servfail, 1.0);
    test::DNSResponder dns2(listen_addr2, listen_srv, 250,
                            ns_rcode::ns_r_servfail, 1.0);
    dns0.addMapping(host_name, ns_type::ns_t_aaaa, "2001:db8::5");
    dns1.addMapping(host_name, ns_type::ns_t_aaaa, "2001:db8::6");
    dns2.addMapping(host_name, ns_type::ns_t_aaaa, "2001:db8::7");
    ASSERT_TRUE(dns0.startServer());
    ASSERT_TRUE(dns1.startServer());
    ASSERT_TRUE(dns2.startServer());
    const std::vector<std::string> servers = { listen_addr0, listen_addr1, listen_addr2 };
    std::vector<std::thread> threads(10);
    for (std::thread& thread : threads) {
       thread = std::thread([this, &servers, &dns0, &dns1, &dns2]() {
            unsigned delay = arc4random_uniform(1*1000*1000); // <= 1s
            usleep(delay);
            std::vector<std::string> serverSubset;
            for (const auto& server : servers) {
                if (arc4random_uniform(2)) {
                    serverSubset.push_back(server);
                }
            }
            if (serverSubset.empty()) serverSubset = servers;
            ASSERT_TRUE(SetResolversForNetwork(mDefaultSearchDomains, serverSubset,
                    mDefaultParams));
            addrinfo hints;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_INET6;
            addrinfo* result = nullptr;
            int rv = getaddrinfo("konbanha", nullptr, &hints, &result);
            EXPECT_EQ(0, rv) << "error [" << rv << "] " << gai_strerror(rv);
        });
    }
    for (std::thread& thread : threads) {
        thread.join();
    }
}
