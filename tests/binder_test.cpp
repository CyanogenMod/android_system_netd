/*
 * Copyright 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * binder_test.cpp - unit tests for netd binder RPCs.
 */

#include <cerrno>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <set>
#include <vector>

#include <fcntl.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include <android-base/macros.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <cutils/multiuser.h>
#include <gtest/gtest.h>
#include <logwrap/logwrap.h>
#include <netutils/ifc.h>

#include "NetdConstants.h"
#include "android/net/INetd.h"
#include "android/net/UidRange.h"
#include "binder/IServiceManager.h"

#define TUN_DEV "/dev/tun"

using namespace android;
using namespace android::base;
using namespace android::binder;
using android::net::INetd;
using android::net::UidRange;

static const char* IP_RULE_V4 = "-4";
static const char* IP_RULE_V6 = "-6";

class BinderTest : public ::testing::Test {

public:
    BinderTest() {
        sp<IServiceManager> sm = defaultServiceManager();
        sp<IBinder> binder = sm->getService(String16("netd"));
        if (binder != nullptr) {
            mNetd = interface_cast<INetd>(binder);
        }
    }

    void SetUp() override {
        ASSERT_NE(nullptr, mNetd.get());
    }

    // Static because setting up the tun interface takes about 40ms.
    static void SetUpTestCase() {
        sTunFd = createTunInterface();
        ASSERT_LE(sTunIfName.size(), static_cast<size_t>(IFNAMSIZ));
        ASSERT_NE(-1, sTunFd);
    }

    static void TearDownTestCase() {
        // Closing the socket removes the interface and IP addresses.
        close(sTunFd);
    }

    static void fakeRemoteSocketPair(int *clientSocket, int *serverSocket, int *acceptedSocket);
    static int createTunInterface();

protected:
    sp<INetd> mNetd;
    static int sTunFd;
    static std::string sTunIfName;
    static in6_addr sSrcAddr, sDstAddr;
    static char sSrcStr[], sDstStr[];
};

int BinderTest::sTunFd;
std::string BinderTest::sTunIfName;
in6_addr BinderTest::sSrcAddr;
in6_addr BinderTest::sDstAddr;
char BinderTest::sSrcStr[INET6_ADDRSTRLEN];
char BinderTest::sDstStr[INET6_ADDRSTRLEN];

class TimedOperation : public Stopwatch {
public:
    TimedOperation(std::string name): mName(name) {}
    virtual ~TimedOperation() {
        fprintf(stderr, "    %s: %6.1f ms\n", mName.c_str(), timeTaken());
    }

private:
    std::string mName;
};

TEST_F(BinderTest, TestIsAlive) {
    TimedOperation t("isAlive RPC");
    bool isAlive = false;
    mNetd->isAlive(&isAlive);
    ASSERT_TRUE(isAlive);
}

static int randomUid() {
    return 100000 * arc4random_uniform(7) + 10000 + arc4random_uniform(5000);
}

static std::vector<std::string> runCommand(const std::string& command) {
    std::vector<std::string> lines;
    FILE *f;

    if ((f = popen(command.c_str(), "r")) == nullptr) {
        perror("popen");
        return lines;
    }

    char *line = nullptr;
    size_t bufsize = 0;
    ssize_t linelen = 0;
    while ((linelen = getline(&line, &bufsize, f)) >= 0) {
        lines.push_back(std::string(line, linelen));
        free(line);
        line = nullptr;
    }

    pclose(f);
    return lines;
}

static std::vector<std::string> listIpRules(const char *ipVersion) {
    std::string command = StringPrintf("%s %s rule list", IP_PATH, ipVersion);
    return runCommand(command);
}

static std::vector<std::string> listIptablesRule(const char *binary, const char *chainName) {
    std::string command = StringPrintf("%s -w -n -L %s", binary, chainName);
    return runCommand(command);
}

static int iptablesRuleLineLength(const char *binary, const char *chainName) {
    return listIptablesRule(binary, chainName).size();
}

TEST_F(BinderTest, TestFirewallReplaceUidChain) {
    std::string chainName = StringPrintf("netd_binder_test_%u", arc4random_uniform(10000));
    const int kNumUids = 500;
    std::vector<int32_t> noUids(0);
    std::vector<int32_t> uids(kNumUids);
    for (int i = 0; i < kNumUids; i++) {
        uids[i] = randomUid();
    }

    bool ret;
    {
        TimedOperation op(StringPrintf("Programming %d-UID whitelist chain", kNumUids));
        mNetd->firewallReplaceUidChain(String16(chainName.c_str()), true, uids, &ret);
    }
    EXPECT_EQ(true, ret);
    EXPECT_EQ((int) uids.size() + 6, iptablesRuleLineLength(IPTABLES_PATH, chainName.c_str()));
    EXPECT_EQ((int) uids.size() + 12, iptablesRuleLineLength(IP6TABLES_PATH, chainName.c_str()));
    {
        TimedOperation op("Clearing whitelist chain");
        mNetd->firewallReplaceUidChain(String16(chainName.c_str()), false, noUids, &ret);
    }
    EXPECT_EQ(true, ret);
    EXPECT_EQ(4, iptablesRuleLineLength(IPTABLES_PATH, chainName.c_str()));
    EXPECT_EQ(4, iptablesRuleLineLength(IP6TABLES_PATH, chainName.c_str()));

    {
        TimedOperation op(StringPrintf("Programming %d-UID blacklist chain", kNumUids));
        mNetd->firewallReplaceUidChain(String16(chainName.c_str()), false, uids, &ret);
    }
    EXPECT_EQ(true, ret);
    EXPECT_EQ((int) uids.size() + 4, iptablesRuleLineLength(IPTABLES_PATH, chainName.c_str()));
    EXPECT_EQ((int) uids.size() + 4, iptablesRuleLineLength(IP6TABLES_PATH, chainName.c_str()));

    {
        TimedOperation op("Clearing blacklist chain");
        mNetd->firewallReplaceUidChain(String16(chainName.c_str()), false, noUids, &ret);
    }
    EXPECT_EQ(true, ret);
    EXPECT_EQ(4, iptablesRuleLineLength(IPTABLES_PATH, chainName.c_str()));
    EXPECT_EQ(4, iptablesRuleLineLength(IP6TABLES_PATH, chainName.c_str()));

    // Check that the call fails if iptables returns an error.
    std::string veryLongStringName = "netd_binder_test_UnacceptablyLongIptablesChainName";
    mNetd->firewallReplaceUidChain(String16(veryLongStringName.c_str()), true, noUids, &ret);
    EXPECT_EQ(false, ret);
}

static int bandwidthDataSaverEnabled(const char *binary) {
    std::vector<std::string> lines = listIptablesRule(binary, "bw_data_saver");

    // Output looks like this:
    //
    // Chain bw_data_saver (1 references)
    // target     prot opt source               destination
    // RETURN     all  --  0.0.0.0/0            0.0.0.0/0
    EXPECT_EQ(3U, lines.size());
    if (lines.size() != 3) return -1;

    EXPECT_TRUE(android::base::StartsWith(lines[2], "RETURN ") ||
                android::base::StartsWith(lines[2], "REJECT "));

    return android::base::StartsWith(lines[2], "REJECT");
}

bool enableDataSaver(sp<INetd>& netd, bool enable) {
    TimedOperation op(enable ? " Enabling data saver" : "Disabling data saver");
    bool ret;
    netd->bandwidthEnableDataSaver(enable, &ret);
    return ret;
}

int getDataSaverState() {
    const int enabled4 = bandwidthDataSaverEnabled(IPTABLES_PATH);
    const int enabled6 = bandwidthDataSaverEnabled(IP6TABLES_PATH);
    EXPECT_EQ(enabled4, enabled6);
    EXPECT_NE(-1, enabled4);
    EXPECT_NE(-1, enabled6);
    if (enabled4 != enabled6 || (enabled6 != 0 && enabled6 != 1)) {
        return -1;
    }
    return enabled6;
}

TEST_F(BinderTest, TestBandwidthEnableDataSaver) {
    const int wasEnabled = getDataSaverState();
    ASSERT_NE(-1, wasEnabled);

    if (wasEnabled) {
        ASSERT_TRUE(enableDataSaver(mNetd, false));
        EXPECT_EQ(0, getDataSaverState());
    }

    ASSERT_TRUE(enableDataSaver(mNetd, false));
    EXPECT_EQ(0, getDataSaverState());

    ASSERT_TRUE(enableDataSaver(mNetd, true));
    EXPECT_EQ(1, getDataSaverState());

    ASSERT_TRUE(enableDataSaver(mNetd, true));
    EXPECT_EQ(1, getDataSaverState());

    if (!wasEnabled) {
        ASSERT_TRUE(enableDataSaver(mNetd, false));
        EXPECT_EQ(0, getDataSaverState());
    }
}

static bool ipRuleExistsForRange(const uint32_t priority, const UidRange& range,
        const std::string& action, const char* ipVersion) {
    // Output looks like this:
    //   "12500:\tfrom all fwmark 0x0/0x20000 iif lo uidrange 1000-2000 prohibit"
    std::vector<std::string> rules = listIpRules(ipVersion);

    std::string prefix = StringPrintf("%" PRIu32 ":", priority);
    std::string suffix = StringPrintf(" iif lo uidrange %d-%d %s\n",
            range.getStart(), range.getStop(), action.c_str());
    for (std::string line : rules) {
        if (android::base::StartsWith(line, prefix.c_str())
                && android::base::EndsWith(line, suffix.c_str())) {
            return true;
        }
    }
    return false;
}

static bool ipRuleExistsForRange(const uint32_t priority, const UidRange& range,
        const std::string& action) {
    bool existsIp4 = ipRuleExistsForRange(priority, range, action, IP_RULE_V4);
    bool existsIp6 = ipRuleExistsForRange(priority, range, action, IP_RULE_V6);
    EXPECT_EQ(existsIp4, existsIp6);
    return existsIp4;
}

TEST_F(BinderTest, TestNetworkRejectNonSecureVpn) {
    constexpr uint32_t RULE_PRIORITY = 12500;

    constexpr int baseUid = MULTIUSER_APP_PER_USER_RANGE * 5;
    std::vector<UidRange> uidRanges = {
        {baseUid + 150, baseUid + 224},
        {baseUid + 226, baseUid + 300}
    };

    const std::vector<std::string> initialRulesV4 = listIpRules(IP_RULE_V4);
    const std::vector<std::string> initialRulesV6 = listIpRules(IP_RULE_V6);

    // Create two valid rules.
    ASSERT_TRUE(mNetd->networkRejectNonSecureVpn(true, uidRanges).isOk());
    EXPECT_EQ(initialRulesV4.size() + 2, listIpRules(IP_RULE_V4).size());
    EXPECT_EQ(initialRulesV6.size() + 2, listIpRules(IP_RULE_V6).size());
    for (auto const& range : uidRanges) {
        EXPECT_TRUE(ipRuleExistsForRange(RULE_PRIORITY, range, "prohibit"));
    }

    // Remove the rules.
    ASSERT_TRUE(mNetd->networkRejectNonSecureVpn(false, uidRanges).isOk());
    EXPECT_EQ(initialRulesV4.size(), listIpRules(IP_RULE_V4).size());
    EXPECT_EQ(initialRulesV6.size(), listIpRules(IP_RULE_V6).size());
    for (auto const& range : uidRanges) {
        EXPECT_FALSE(ipRuleExistsForRange(RULE_PRIORITY, range, "prohibit"));
    }

    // Fail to remove the rules a second time after they are already deleted.
    binder::Status status = mNetd->networkRejectNonSecureVpn(false, uidRanges);
    ASSERT_EQ(binder::Status::EX_SERVICE_SPECIFIC, status.exceptionCode());
    EXPECT_EQ(ENOENT, status.serviceSpecificErrorCode());

    // All rules should be the same as before.
    EXPECT_EQ(initialRulesV4, listIpRules(IP_RULE_V4));
    EXPECT_EQ(initialRulesV6, listIpRules(IP_RULE_V6));
}

int BinderTest::createTunInterface() {
    // Generate a random ULA address pair.
    arc4random_buf(&sSrcAddr, sizeof(sSrcAddr));
    sSrcAddr.s6_addr[0] = 0xfd;
    memcpy(&sDstAddr, &sSrcAddr, sizeof(sDstAddr));
    sDstAddr.s6_addr[15] ^= 1;

    // Convert the addresses to strings because that's what ifc_add_address takes.
    sockaddr_in6 src6 = { .sin6_family = AF_INET6, .sin6_addr = sSrcAddr, };
    sockaddr_in6 dst6 = { .sin6_family = AF_INET6, .sin6_addr = sDstAddr, };
    int flags = NI_NUMERICHOST;
    if (getnameinfo((sockaddr *) &src6, sizeof(src6), sSrcStr, sizeof(sSrcStr), NULL, 0, flags) ||
        getnameinfo((sockaddr *) &dst6, sizeof(dst6), sDstStr, sizeof(sDstStr), NULL, 0, flags)) {
        return -1;
    }

    // Create a tun interface with a name based on our PID.
    sTunIfName = StringPrintf("netdtest%u", getpid());
    struct ifreq ifr = {
        .ifr_ifru = { .ifru_flags = IFF_TUN },
    };
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", sTunIfName.c_str());

    int fd = open(TUN_DEV, O_RDWR | O_NONBLOCK | O_CLOEXEC);
    EXPECT_NE(-1, fd) << TUN_DEV << ": " << strerror(errno);
    if (fd == -1) return fd;

    int ret = ioctl(fd, TUNSETIFF, &ifr, sizeof(ifr));
    EXPECT_EQ(0, ret) << "TUNSETIFF: " << strerror(errno);
    if (ret) {
        close(fd);
        return -1;
    }

    if (ifc_add_address(ifr.ifr_name, sSrcStr, 64) ||
        ifc_add_address(ifr.ifr_name, sDstStr, 64)) {
        close(fd);
        return -1;
    }
    return fd;
}

// Create a socket pair that isLoopbackSocket won't think is local.
void BinderTest::fakeRemoteSocketPair(int *clientSocket, int *serverSocket, int *acceptedSocket) {
    *serverSocket = socket(AF_INET6, SOCK_STREAM, 0);
    struct sockaddr_in6 server6 = { .sin6_family = AF_INET6, .sin6_addr = sDstAddr };
    ASSERT_EQ(0, bind(*serverSocket, (struct sockaddr *) &server6, sizeof(server6)));

    socklen_t addrlen = sizeof(server6);
    ASSERT_EQ(0, getsockname(*serverSocket, (struct sockaddr *) &server6, &addrlen));
    ASSERT_EQ(0, listen(*serverSocket, 10));

    *clientSocket = socket(AF_INET6, SOCK_STREAM, 0);
    struct sockaddr_in6 client6 = { .sin6_family = AF_INET6, .sin6_addr = sSrcAddr };
    ASSERT_EQ(0, bind(*clientSocket, (struct sockaddr *) &client6, sizeof(client6)));
    ASSERT_EQ(0, connect(*clientSocket, (struct sockaddr *) &server6, sizeof(server6)));
    ASSERT_EQ(0, getsockname(*clientSocket, (struct sockaddr *) &client6, &addrlen));

    *acceptedSocket = accept(*serverSocket, (struct sockaddr *) &server6, &addrlen);
    ASSERT_NE(-1, *acceptedSocket);

    ASSERT_EQ(0, memcmp(&client6, &server6, sizeof(client6)));
}

void checkSocketpairOpen(int clientSocket, int acceptedSocket) {
    char buf[4096];
    EXPECT_EQ(4, write(clientSocket, "foo", sizeof("foo")));
    EXPECT_EQ(4, read(acceptedSocket, buf, sizeof(buf)));
    EXPECT_EQ(0, memcmp(buf, "foo", sizeof("foo")));
}

void checkSocketpairClosed(int clientSocket, int acceptedSocket) {
    // Check that the client socket was closed with ECONNABORTED.
    int ret = write(clientSocket, "foo", sizeof("foo"));
    int err = errno;
    EXPECT_EQ(-1, ret);
    EXPECT_EQ(ECONNABORTED, err);

    // Check that it sent a RST to the server.
    ret = write(acceptedSocket, "foo", sizeof("foo"));
    err = errno;
    EXPECT_EQ(-1, ret);
    EXPECT_EQ(ECONNRESET, err);
}

TEST_F(BinderTest, TestSocketDestroy) {
    int clientSocket, serverSocket, acceptedSocket;
    ASSERT_NO_FATAL_FAILURE(fakeRemoteSocketPair(&clientSocket, &serverSocket, &acceptedSocket));

    // Pick a random UID in the system UID range.
    constexpr int baseUid = AID_APP - 2000;
    static_assert(baseUid > 0, "Not enough UIDs? Please fix this test.");
    int uid = baseUid + 500 + arc4random_uniform(1000);
    EXPECT_EQ(0, fchown(clientSocket, uid, -1));

    // UID ranges that don't contain uid.
    std::vector<UidRange> uidRanges = {
        {baseUid + 42, baseUid + 449},
        {baseUid + 1536, AID_APP - 4},
        {baseUid + 498, uid - 1},
        {uid + 1, baseUid + 1520},
    };
    // A skip list that doesn't contain UID.
    std::vector<int32_t> skipUids { baseUid + 123, baseUid + 1600 };

    // Close sockets. Our test socket should be intact.
    EXPECT_TRUE(mNetd->socketDestroy(uidRanges, skipUids).isOk());
    checkSocketpairOpen(clientSocket, acceptedSocket);

    // UID ranges that do contain uid.
    uidRanges = {
        {baseUid + 42, baseUid + 449},
        {baseUid + 1536, AID_APP - 4},
        {baseUid + 498, baseUid + 1520},
    };
    // Add uid to the skip list.
    skipUids.push_back(uid);

    // Close sockets. Our test socket should still be intact because it's in the skip list.
    EXPECT_TRUE(mNetd->socketDestroy(uidRanges, skipUids).isOk());
    checkSocketpairOpen(clientSocket, acceptedSocket);

    // Now remove uid from skipUids, and close sockets. Our test socket should have been closed.
    skipUids.resize(skipUids.size() - 1);
    EXPECT_TRUE(mNetd->socketDestroy(uidRanges, skipUids).isOk());
    checkSocketpairClosed(clientSocket, acceptedSocket);

    close(clientSocket);
    close(serverSocket);
    close(acceptedSocket);
}

namespace {

int netmaskToPrefixLength(const uint8_t *buf, size_t buflen) {
    if (buf == nullptr) return -1;

    int prefixLength = 0;
    bool endOfContiguousBits = false;
    for (unsigned int i = 0; i < buflen; i++) {
        const uint8_t value = buf[i];

        // Bad bit sequence: check for a contiguous set of bits from the high
        // end by verifying that the inverted value + 1 is a power of 2
        // (power of 2 iff. (v & (v - 1)) == 0).
        const uint8_t inverse = ~value + 1;
        if ((inverse & (inverse - 1)) != 0) return -1;

        prefixLength += (value == 0) ? 0 : CHAR_BIT - ffs(value) + 1;

        // Bogus netmask.
        if (endOfContiguousBits && value != 0) return -1;

        if (value != 0xff) endOfContiguousBits = true;
    }

    return prefixLength;
}

template<typename T>
int netmaskToPrefixLength(const T *p) {
    return netmaskToPrefixLength(reinterpret_cast<const uint8_t*>(p), sizeof(T));
}


static bool interfaceHasAddress(
        const std::string &ifname, const char *addrString, int prefixLength) {
    struct addrinfo *addrinfoList = nullptr;
    ScopedAddrinfo addrinfoCleanup(addrinfoList);

    const struct addrinfo hints = {
        .ai_flags    = AI_NUMERICHOST,
        .ai_family   = AF_UNSPEC,
        .ai_socktype = SOCK_DGRAM,
    };
    if (getaddrinfo(addrString, nullptr, &hints, &addrinfoList) != 0 ||
        addrinfoList == nullptr || addrinfoList->ai_addr == nullptr) {
        return false;
    }

    struct ifaddrs *ifaddrsList = nullptr;
    ScopedIfaddrs ifaddrsCleanup(ifaddrsList);

    if (getifaddrs(&ifaddrsList) != 0) {
        return false;
    }

    for (struct ifaddrs *addr = ifaddrsList; addr != nullptr; addr = addr->ifa_next) {
        if (std::string(addr->ifa_name) != ifname ||
            addr->ifa_addr == nullptr ||
            addr->ifa_addr->sa_family != addrinfoList->ai_addr->sa_family) {
            continue;
        }

        switch (addr->ifa_addr->sa_family) {
        case AF_INET: {
            auto *addr4 = reinterpret_cast<const struct sockaddr_in*>(addr->ifa_addr);
            auto *want = reinterpret_cast<const struct sockaddr_in*>(addrinfoList->ai_addr);
            if (memcmp(&addr4->sin_addr, &want->sin_addr, sizeof(want->sin_addr)) != 0) {
                continue;
            }

            if (prefixLength < 0) return true;  // not checking prefix lengths

            if (addr->ifa_netmask == nullptr) return false;
            auto *nm = reinterpret_cast<const struct sockaddr_in*>(addr->ifa_netmask);
            EXPECT_EQ(prefixLength, netmaskToPrefixLength(&nm->sin_addr));
            return (prefixLength == netmaskToPrefixLength(&nm->sin_addr));
        }
        case AF_INET6: {
            auto *addr6 = reinterpret_cast<const struct sockaddr_in6*>(addr->ifa_addr);
            auto *want = reinterpret_cast<const struct sockaddr_in6*>(addrinfoList->ai_addr);
            if (memcmp(&addr6->sin6_addr, &want->sin6_addr, sizeof(want->sin6_addr)) != 0) {
                continue;
            }

            if (prefixLength < 0) return true;  // not checking prefix lengths

            if (addr->ifa_netmask == nullptr) return false;
            auto *nm = reinterpret_cast<const struct sockaddr_in6*>(addr->ifa_netmask);
            EXPECT_EQ(prefixLength, netmaskToPrefixLength(&nm->sin6_addr));
            return (prefixLength == netmaskToPrefixLength(&nm->sin6_addr));
        }
        default:
            // Cannot happen because we have already screened for matching
            // address families at the top of each iteration.
            continue;
        }
    }

    return false;
}

}  // namespace

TEST_F(BinderTest, TestInterfaceAddRemoveAddress) {
    static const struct TestData {
        const char *addrString;
        const int   prefixLength;
        const bool  expectSuccess;
    } kTestData[] = {
        { "192.0.2.1", 24, true },
        { "192.0.2.2", 25, true },
        { "192.0.2.3", 32, true },
        { "192.0.2.4", 33, false },
        { "192.not.an.ip", 24, false },
        { "2001:db8::1", 64, true },
        { "2001:db8::2", 65, true },
        { "2001:db8::3", 128, true },
        { "2001:db8::4", 129, false },
        { "foo:bar::bad", 64, false },
    };

    for (unsigned int i = 0; i < arraysize(kTestData); i++) {
        const auto &td = kTestData[i];

        // [1.a] Add the address.
        binder::Status status = mNetd->interfaceAddAddress(
                sTunIfName, td.addrString, td.prefixLength);
        if (td.expectSuccess) {
            EXPECT_TRUE(status.isOk()) << status.exceptionMessage();
        } else {
            ASSERT_EQ(binder::Status::EX_SERVICE_SPECIFIC, status.exceptionCode());
            ASSERT_NE(0, status.serviceSpecificErrorCode());
        }

        // [1.b] Verify the addition meets the expectation.
        if (td.expectSuccess) {
            EXPECT_TRUE(interfaceHasAddress(sTunIfName, td.addrString, td.prefixLength));
        } else {
            EXPECT_FALSE(interfaceHasAddress(sTunIfName, td.addrString, -1));
        }

        // [2.a] Try to remove the address.  If it was not previously added, removing it fails.
        status = mNetd->interfaceDelAddress(sTunIfName, td.addrString, td.prefixLength);
        if (td.expectSuccess) {
            EXPECT_TRUE(status.isOk()) << status.exceptionMessage();
        } else {
            ASSERT_EQ(binder::Status::EX_SERVICE_SPECIFIC, status.exceptionCode());
            ASSERT_NE(0, status.serviceSpecificErrorCode());
        }

        // [2.b] No matter what, the address should not be present.
        EXPECT_FALSE(interfaceHasAddress(sTunIfName, td.addrString, -1));
    }
}
