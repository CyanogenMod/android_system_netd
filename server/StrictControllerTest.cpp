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
 * StrictControllerTest.cpp - unit tests for StrictController.cpp
 */

#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <android-base/strings.h>

#include "StrictController.h"
#include "IptablesBaseTest.h"

class StrictControllerTest : public IptablesBaseTest {
public:
    StrictControllerTest() {
        StrictController::execIptables = fakeExecIptables;
    }
    StrictController mStrictCtrl;
};

TEST_F(StrictControllerTest, TestEnableStrict) {
    mStrictCtrl.enableStrict();

    std::vector<std::pair<IptablesTarget, std::string>> expected = {
        { V4V6, "-F st_OUTPUT" },
        { V4V6, "-F st_penalty_log" },
        { V4V6, "-F st_penalty_reject" },
        { V4V6, "-F st_clear_caught" },
        { V4V6, "-F st_clear_detect" },
        { V4V6, "-X st_penalty_log" },
        { V4V6, "-X st_penalty_reject" },
        { V4V6, "-X st_clear_caught" },
        { V4V6, "-X st_clear_detect" },
        { V4V6, "-N st_penalty_log" },
        { V4V6, "-A st_penalty_log -j CONNMARK --or-mark 0x1000000" },
        { V4V6, "-A st_penalty_log -j NFLOG --nflog-group 0" },
        { V4V6, "-N st_penalty_reject" },
        { V4V6, "-A st_penalty_reject -j CONNMARK --or-mark 0x2000000" },
        { V4V6, "-A st_penalty_reject -j NFLOG --nflog-group 0" },
        { V4V6, "-A st_penalty_reject -j REJECT" },
        { V4V6, "-N st_clear_detect" },
        { V4V6, "-N st_clear_caught" },
        { V4V6, "-A st_clear_detect -m connmark --mark 0x2000000/0x2000000 -j REJECT" },
        { V4V6, "-A st_clear_detect -m connmark --mark 0x1000000/0x1000000 -j RETURN" },
        { V4, "-A st_clear_detect -p tcp -m u32 --u32 "
              "0>>22&0x3C@ 12>>26&0x3C@ 0&0xFFFF0000=0x16030000 &&"
              "0>>22&0x3C@ 12>>26&0x3C@ 4&0x00FF0000=0x00010000 "
              "-j CONNMARK --or-mark 0x1000000" },
        { V4, "-A st_clear_detect -p udp -m u32 --u32 "
              "0>>22&0x3C@ 8&0xFFFF0000=0x16FE0000 &&"
              "0>>22&0x3C@ 20&0x00FF0000=0x00010000"
              " -j CONNMARK --or-mark 0x1000000" },
        { V6, "-A st_clear_detect -p tcp -m u32 --u32 "
              "52>>26&0x3C@ 40&0xFFFF0000=0x16030000 &&"
              "52>>26&0x3C@ 44&0x00FF0000=0x00010000"
              " -j CONNMARK --or-mark 0x1000000" },
        { V6, "-A st_clear_detect -p udp -m u32 --u32 "
              "48&0xFFFF0000=0x16FE0000 &&60&0x00FF0000=0x00010000"
              " -j CONNMARK --or-mark 0x1000000" },
        { V4V6, "-A st_clear_detect -m connmark --mark 0x1000000/0x1000000 -j RETURN" },
        { V4, "-A st_clear_detect -p tcp -m state --state ESTABLISHED -m u32 --u32 "
              "0>>22&0x3C@ 12>>26&0x3C@ 0&0x0=0x0"
              " -j st_clear_caught" },
        { V6, "-A st_clear_detect -p tcp -m state --state ESTABLISHED -m u32 --u32 "
              "52>>26&0x3C@ 40&0x0=0x0"
              " -j st_clear_caught" },
        { V4V6, "-A st_clear_detect -p udp -j st_clear_caught" },
    };
    expectIptablesCommands(expected);
}

TEST_F(StrictControllerTest, TestDisableStrict) {
    mStrictCtrl.disableStrict();

    std::vector<std::string> expected = {
        "-F st_OUTPUT",
        "-F st_penalty_log",
        "-F st_penalty_reject",
        "-F st_clear_caught",
        "-F st_clear_detect",
        "-X st_penalty_log",
        "-X st_penalty_reject",
        "-X st_clear_caught",
        "-X st_clear_detect",
    };
    expectIptablesCommands(expected);
}
