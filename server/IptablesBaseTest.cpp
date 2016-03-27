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
 * IptablesBaseTest.cpp - utility class for tests that use iptables
 */

#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "IptablesBaseTest.h"
#include "NetdConstants.h"

IptablesBaseTest::IptablesBaseTest() {
    sCmds.clear();
    sRestoreCmds.clear();
}

int IptablesBaseTest::fake_android_fork_exec(int argc, char* argv[], int *status, bool, bool) {
    std::string cmd = argv[0];
    for (int i = 1; i < argc; i++) {
        cmd += " ";
        cmd += argv[i];
    }
    sCmds.push_back(cmd);
    *status = 0;
    return 0;
}

int IptablesBaseTest::fakeExecIptables(IptablesTarget target, ...) {
    std::string cmd = " -w";
    va_list args;
    va_start(args, target);
    const char *arg;
    do {
        arg = va_arg(args, const char *);
        if (arg != nullptr) {
            cmd += " ";
            cmd += arg;
        }
    } while (arg);

    if (target == V4 || target == V4V6) {
        sCmds.push_back(IPTABLES_PATH + cmd);
    }
    if (target == V6 || target == V4V6) {
        sCmds.push_back(IP6TABLES_PATH + cmd);
    }

    return 0;
}

int IptablesBaseTest::fakeExecIptablesRestore(IptablesTarget target, const std::string& commands) {
    EXPECT_EQ(V4V6, target);
    sRestoreCmds.push_back(commands);
    return 0;
}

int IptablesBaseTest::expectIptablesCommand(IptablesTarget target, int pos,
                                            const std::string& cmd) {
    if (target == V4 || target == V4V6) {
        EXPECT_EQ("/system/bin/iptables -w " + cmd, sCmds[pos++]);
    }
    if (target == V6 || target == V4V6) {
        EXPECT_EQ("/system/bin/ip6tables -w " + cmd, sCmds[pos++]);
    }
    return target == V4V6 ? 2 : 1;
}

void IptablesBaseTest::expectIptablesCommands(const std::vector<std::string>& expectedCmds) {
    ExpectedIptablesCommands expected;
    for (auto cmd : expectedCmds) {
        expected.push_back({ V4V6, cmd });
    }
    expectIptablesCommands(expected);
}

void IptablesBaseTest::expectIptablesCommands(const ExpectedIptablesCommands& expectedCmds) {
    size_t pos = 0;
    for (size_t i = 0; i < expectedCmds.size(); i ++) {
        auto target = expectedCmds[i].first;
        auto cmd = expectedCmds[i].second;
        pos += expectIptablesCommand(target, pos, cmd);
    }

    EXPECT_EQ(pos, sCmds.size());
    sCmds.clear();
}

void IptablesBaseTest::expectIptablesRestoreCommands(const std::vector<std::string>& expectedCmds) {
    EXPECT_EQ(expectedCmds.size(), sRestoreCmds.size());
    EXPECT_EQ(expectedCmds, sRestoreCmds);
    sRestoreCmds.clear();
}

std::vector<std::string> IptablesBaseTest::sCmds = {};
std::vector<std::string> IptablesBaseTest::sRestoreCmds = {};
