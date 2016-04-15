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

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <gtest/gtest.h>
#include <logwrap/logwrap.h>

#include "NetdConstants.h"
#include "android/net/INetd.h"
#include "binder/IServiceManager.h"

using namespace android;
using namespace android::base;
using namespace android::binder;
using android::net::INetd;

class BinderTest : public ::testing::Test {

public:
    BinderTest() {
        sp<IServiceManager> sm = defaultServiceManager();
        sp<IBinder> binder = sm->getService(String16("netd"));
        if (binder != nullptr) {
            mNetd = interface_cast<INetd>(binder);
        }
    }

    void SetUp() {
        ASSERT_NE(nullptr, mNetd.get());
    }

protected:
    sp<INetd> mNetd;
};


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

static std::vector<std::string> listIptablesRule(const char *binary, const char *chainName) {
    std::vector<std::string> lines;
    FILE *f;

    std::string command = StringPrintf("%s -n -L %s", binary, chainName);
    if ((f = popen(command.c_str(), "r")) == nullptr) {
        perror("popen");
        return lines;
    }

    char *line = nullptr;
    size_t linelen = 0;
    while (getline(&line, &linelen, f) >= 0) {
        lines.push_back(std::string(line, linelen));
        free(line);
        line = nullptr;
    }

    pclose(f);
    return lines;
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
    EXPECT_EQ((int) uids.size() + 4, iptablesRuleLineLength(IPTABLES_PATH, chainName.c_str()));
    EXPECT_EQ((int) uids.size() + 4, iptablesRuleLineLength(IP6TABLES_PATH, chainName.c_str()));
    {
        TimedOperation op("Clearing whitelist chain");
        mNetd->firewallReplaceUidChain(String16(chainName.c_str()), false, noUids, &ret);
    }
    EXPECT_EQ(true, ret);
    EXPECT_EQ(2, iptablesRuleLineLength(IPTABLES_PATH, chainName.c_str()));
    EXPECT_EQ(2, iptablesRuleLineLength(IP6TABLES_PATH, chainName.c_str()));

    {
        TimedOperation op(StringPrintf("Programming %d-UID blacklist chain", kNumUids));
        mNetd->firewallReplaceUidChain(String16(chainName.c_str()), false, uids, &ret);
    }
    EXPECT_EQ(true, ret);
    EXPECT_EQ((int) uids.size() + 3, iptablesRuleLineLength(IPTABLES_PATH, chainName.c_str()));
    EXPECT_EQ((int) uids.size() + 3, iptablesRuleLineLength(IP6TABLES_PATH, chainName.c_str()));

    {
        TimedOperation op("Clearing blacklist chain");
        mNetd->firewallReplaceUidChain(String16(chainName.c_str()), false, noUids, &ret);
    }
    EXPECT_EQ(true, ret);
    EXPECT_EQ(2, iptablesRuleLineLength(IPTABLES_PATH, chainName.c_str()));
    EXPECT_EQ(2, iptablesRuleLineLength(IP6TABLES_PATH, chainName.c_str()));

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
