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
 * FirewallControllerTest.cpp - unit tests for FirewallController.cpp
 */

#include <string>
#include <vector>
#include <stdio.h>

#include <gtest/gtest.h>

#include "FirewallController.h"


class FirewallControllerTest : public ::testing::Test {
protected:
    FirewallController mFw;
    std::string makeUidRules(const char *a, bool b, const std::vector<int32_t>& c) {
        return mFw.makeUidRules(a, b, c);
    }
};


TEST_F(FirewallControllerTest, TestWhitelist) {
    std::string expected =
            "*filter\n"
            ":FW_whitechain -\n"
            "-A FW_whitechain -m owner --uid-owner 0-9999 -j RETURN\n"
            "-A FW_whitechain -m owner --uid-owner 10023 -j RETURN\n"
            "-A FW_whitechain -m owner --uid-owner 10059 -j RETURN\n"
            "-A FW_whitechain -m owner --uid-owner 10124 -j RETURN\n"
            "-A FW_whitechain -m owner --uid-owner 10111 -j RETURN\n"
            "-A FW_whitechain -m owner --uid-owner 110122 -j RETURN\n"
            "-A FW_whitechain -m owner --uid-owner 210153 -j RETURN\n"
            "-A FW_whitechain -m owner --uid-owner 210024 -j RETURN\n"
            "-A FW_whitechain -j DROP\n"
            "COMMIT\n\x04";

    std::vector<int32_t> uids = { 10023, 10059, 10124, 10111, 110122, 210153, 210024 };
    EXPECT_EQ(expected, makeUidRules("FW_whitechain", true, uids));
}

TEST_F(FirewallControllerTest, TestBlacklist) {
    std::string expected =
            "*filter\n"
            ":FW_blackchain -\n"
            "-A FW_blackchain -m owner --uid-owner 10023 -j DROP\n"
            "-A FW_blackchain -m owner --uid-owner 10059 -j DROP\n"
            "-A FW_blackchain -m owner --uid-owner 10124 -j DROP\n"
            "-A FW_blackchain -j RETURN\n"
            "COMMIT\n\x04";

    std::vector<int32_t> uids = { 10023, 10059, 10124 };
    EXPECT_EQ(expected, makeUidRules("FW_blackchain", false, uids));
}
