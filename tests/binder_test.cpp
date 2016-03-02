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

#include <cstdlib>
#include <cstdint>
#include <vector>

#include <android-base/stringprintf.h>
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


class TimedOperation {
public:
    TimedOperation(std::string name): mStart(std::chrono::steady_clock::now()), mName(name) {}
    virtual ~TimedOperation() {
        using ms = std::chrono::duration<float, std::ratio<1, 1000>>;
        fprintf(stderr, "    %s: %6.1f ms\n", mName.c_str(),
                std::chrono::duration_cast<ms>(std::chrono::steady_clock::now() - mStart).count());
    }

private:
    std::chrono::time_point<std::chrono::steady_clock> mStart;
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

static int countNewlines(FILE *f) {
    char buf[4096];
    int numNewlines = 0;
    size_t bytesread;
    while ((bytesread = fread(buf, 1, sizeof(buf), f)) > 0) {
        for (size_t i = 0; i < bytesread; i++) {
            if (buf[i] == '\n') {
                numNewlines++;
            }
        }
    }
    return numNewlines;
}

static int ruleLineLength(const char *binary, const char *chainName) {
    FILE *f;
    std::string command = StringPrintf("%s -n -L %s", binary, chainName);
    if ((f = popen(command.c_str(), "r")) == NULL) {
        perror("popen");
        return -1;
    }
    int numLines = countNewlines(f);
    pclose(f);
    return numLines;
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
    EXPECT_EQ((int) uids.size() + 4, ruleLineLength(IPTABLES_PATH, chainName.c_str()));
    EXPECT_EQ((int) uids.size() + 4, ruleLineLength(IP6TABLES_PATH, chainName.c_str()));
    {
        TimedOperation op("Clearing whitelist chain");
        mNetd->firewallReplaceUidChain(String16(chainName.c_str()), false, noUids, &ret);
    }
    EXPECT_EQ(true, ret);
    EXPECT_EQ(2, ruleLineLength(IPTABLES_PATH, chainName.c_str()));
    EXPECT_EQ(2, ruleLineLength(IP6TABLES_PATH, chainName.c_str()));

    {
        TimedOperation op(StringPrintf("Programming %d-UID blacklist chain", kNumUids));
        mNetd->firewallReplaceUidChain(String16(chainName.c_str()), false, uids, &ret);
    }
    EXPECT_EQ(true, ret);
    EXPECT_EQ((int) uids.size() + 3, ruleLineLength(IPTABLES_PATH, chainName.c_str()));
    EXPECT_EQ((int) uids.size() + 3, ruleLineLength(IP6TABLES_PATH, chainName.c_str()));

    {
        TimedOperation op("Clearing blacklist chain");
        mNetd->firewallReplaceUidChain(String16(chainName.c_str()), false, noUids, &ret);
    }
    EXPECT_EQ(true, ret);
    EXPECT_EQ(2, ruleLineLength(IPTABLES_PATH, chainName.c_str()));
    EXPECT_EQ(2, ruleLineLength(IP6TABLES_PATH, chainName.c_str()));

    // Check that the call fails if iptables returns an error.
    std::string veryLongStringName = "netd_binder_test_UnacceptablyLongIptablesChainName";
    mNetd->firewallReplaceUidChain(String16(veryLongStringName.c_str()), true, noUids, &ret);
    EXPECT_EQ(false, ret);
}
